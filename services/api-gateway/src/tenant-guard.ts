import { Inject, HttpException, type CanActivate, type ExecutionContext } from '@nestjs/common';
import type { Request } from 'express';
import { Authenticator, type Principal } from '../../identity-service/auth.js';
import type { RequestLimiter } from '../../../core/tenant-authorization/src/rate-limit.js';
export type TenantRequest = Request & Principal;
export class TenantGuard implements CanActivate {
  constructor(
    @Inject('AUTH') private readonly auth: Authenticator,
    @Inject('LIMITER') private readonly limiter: RequestLimiter,
  ) {}
  async canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest<TenantRequest>();
    const principal = await this.auth.authenticate(request.headers.authorization);
    if (!principal) throw new HttpException('Valid tenant credential required', 401);
    if (!['GET', 'HEAD'].includes(request.method) && principal.role === 'viewer')
      throw new HttpException('Analyst role required', 403);
    if (['PATCH', 'DELETE'].includes(request.method) && principal.role !== 'admin')
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
