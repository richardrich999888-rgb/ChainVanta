import 'reflect-metadata';
import {
  ArgumentsHost,
  Body,
  CanActivate,
  Catch,
  Controller,
  ExecutionContext,
  ExceptionFilter,
  Get,
  HttpException,
  Inject,
  Module,
  Param,
  Post,
  Patch,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { json, type Request, type Response } from 'express';
import helmet from 'helmet';
import { z } from 'zod';
import {
  ModuleCatalog,
  ScanRequest,
  FindingUpdate,
  canonicalAssetId,
  Address,
} from '../../../packages/domain-models/src/index.js';
import type { Config } from '../../../packages/config/src/index.js';
import { Authenticator, type Principal } from '../../identity-service/auth.js';
import {
  TestLimiter,
  type RequestLimiter,
} from '../../../core/tenant-authorization/src/rate-limit.js';
import { report, compareSnapshots } from '../../../core/reporting-engine/src/index.js';
import { RpcFailure } from '../../../connectors/blockchains/ethereum/src/index.js';
import { AssessmentService } from '../../assessment-service/src/index.js';
import type { Repository } from '../../inventory-service/src/repository.js';

type TenantRequest = Request & Principal;
class TenantGuard implements CanActivate {
  constructor(
    @Inject('AUTH') private readonly auth: Authenticator,
    @Inject('LIMITER') private limiter: RequestLimiter,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<TenantRequest>();
    const principal = await this.auth.authenticate(request.headers.authorization);
    if (!principal) throw new HttpException('Valid tenant credential required', 401);
    if (!['GET', 'HEAD'].includes(request.method) && principal.role === 'viewer')
      throw new HttpException('Analyst role required', 403);
    if (request.method === 'PATCH' && principal.role !== 'admin')
      throw new HttpException('Admin role required', 403);
    try {
      if (!(await this.limiter.consume(principal.tenantId)))
        throw new HttpException('Request limit reached; retry in one minute', 429);
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new HttpException('Rate limiter unavailable', 503);
    }
    Object.assign(request, principal);
    return true;
  }
}

@Catch()
class ApiErrors implements ExceptionFilter {
  catch(error: unknown, host: ArgumentsHost) {
    const response = host.switchToHttp().getResponse<Response>();
    let status = 500;
    let message = 'Request failed; retry or contact the operator';
    if (error instanceof z.ZodError) {
      status = 400;
      message = 'Invalid request input';
    } else if (error instanceof RpcFailure) {
      status = 502;
      message = error.message;
    } else if (error instanceof HttpException) {
      status = error.getStatus();
      message = error.message;
    } else if (
      error &&
      typeof error === 'object' &&
      'type' in error &&
      error.type === 'entity.too.large'
    ) {
      status = 413;
      message = 'Request body too large';
    } else if (error instanceof SyntaxError) {
      status = 400;
      message = 'Malformed JSON';
    }
    if (status === 500) console.error(JSON.stringify({ event: 'request_failed', status }));
    response.status(status).json({ error: { status, message } });
  }
}

@Controller('v1')
@UseGuards(TenantGuard)
class ApiController {
  constructor(@Inject('SERVICE') private readonly service: AssessmentService) {}
  @Get('session') session(@Req() request: TenantRequest) {
    return { tenantId: request.tenantId, role: request.role };
  }
  @Get('chains') chains() {
    return this.service.chains.map(({ chainId, name }) => ({ chainId, name }));
  }
  @Get('modules') modules() {
    return ModuleCatalog.map(([id, name, status]) => ({ id, name, status }));
  }
  @Get('assessments') list(@Req() request: TenantRequest) {
    return this.service.repository.list(request.tenantId);
  }
  @Get('assessments/:id') async get(@Req() request: TenantRequest, @Param('id') id: string) {
    const result = await this.service.repository.get(request.tenantId, z.uuid().parse(id));
    if (!result) throw new HttpException('Assessment not found', 404);
    return result;
  }
  @Get('reports') async reports(@Req() request: TenantRequest) {
    return report(await this.service.repository.list(request.tenantId));
  }
  @Get('audit') audit(@Req() request: TenantRequest) {
    if (request.role !== 'admin') throw new HttpException('Admin role required', 403);
    return this.service.repository.audit?.(request.tenantId) ?? [];
  }
  @Get('findings/events') events(@Req() request: TenantRequest) {
    return this.service.repository.findingEvents?.(request.tenantId) ?? [];
  }
  @Patch('assessments/:id/findings/:ruleId') async update(
    @Req() request: TenantRequest,
    @Param('id') id: string,
    @Param('ruleId') ruleId: string,
    @Body() body: unknown,
  ) {
    await this.service.repository.findingEvent?.(
      request.tenantId,
      z.uuid().parse(id),
      z.string().max(80).parse(ruleId),
      FindingUpdate.parse(body),
      request.subject,
    );
    return { ok: true };
  }
  @Get('history') async history(
    @Req() request: TenantRequest,
    @Query('chainId') chainId: string,
    @Query('address') address: string,
  ) {
    const asset = canonicalAssetId(
      z.coerce.number().int().positive().safe().parse(chainId),
      Address.parse(address),
    );
    const items = (await this.service.repository.history?.(request.tenantId, asset)) ?? [];
    return {
      assessments: items,
      drift: items[0] && items[1] ? compareSnapshots(items[0], items[1]) : [],
    };
  }
  @Get('graph') graph(@Req() request: TenantRequest, @Query('source') source: string) {
    return (
      this.service.repository.graph?.(request.tenantId, z.string().min(1).max(150).parse(source)) ??
      []
    );
  }
  @Post('assessments') scan(@Req() request: TenantRequest, @Body() body: unknown) {
    const key = request.headers['idempotency-key'];
    return this.service.scan(
      request.tenantId,
      ScanRequest.parse(body),
      key === undefined
        ? undefined
        : z
            .string()
            .regex(/^[a-zA-Z0-9_-]{8,128}$/)
            .parse(key),
      request.subject,
    );
  }
}

@Controller('health')
class HealthController {
  constructor(
    @Inject('SERVICE') private readonly service: AssessmentService,
    @Inject('LIMITER') private limiter: RequestLimiter,
  ) {}
  @Get('live') live() {
    return { status: 'ok' };
  }
  @Get('ready') async ready() {
    try {
      await this.service.repository.ping();
      await this.limiter.ping();
      return { status: 'ready' };
    } catch {
      throw new HttpException('Database not ready', 503);
    }
  }
}

export async function createApp(
  config: Pick<Config, 'tenantKeys' | 'chains'> & Partial<Pick<Config, 'oidc'>>,
  repository: Repository,
  transport: typeof fetch = fetch,
  limiter: RequestLimiter = new TestLimiter(),
) {
  @Module({
    controllers: [ApiController, HealthController],
    providers: [
      { provide: 'AUTH', useValue: new Authenticator(config.tenantKeys, config.oidc) },
      { provide: 'LIMITER', useValue: limiter },
      { provide: 'SERVICE', useValue: new AssessmentService(repository, config.chains, transport) },
      TenantGuard,
    ],
  })
  class AppModule {}
  const app = await NestFactory.create(AppModule, { bodyParser: false, logger: ['error', 'warn'] });
  app.use(helmet());
  app.use(json({ limit: '8kb' }));
  app.use((_request: Request, response: Response, next: () => void) => {
    response.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.useGlobalFilters(new ApiErrors());
  app.enableShutdownHooks();
  return app;
}
