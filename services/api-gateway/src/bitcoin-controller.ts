import {
  Body,
  Controller,
  Get,
  Header,
  HttpException,
  Inject,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { z } from 'zod';
import { TenantGuard, type TenantRequest } from './tenant-guard.js';
import { BitcoinScanRequest } from '../../../packages/domain-models/src/bitcoin.js';
import {
  CDX_MEDIA_TYPE,
  toCycloneDxBitcoin,
} from '../../../core/cbom-engine/exporters/cyclonedx.js';
import type { BitcoinAssessmentService } from '../../assessment-service/src/bitcoin.js';

const IdempotencyKey = z.string().regex(/^[a-zA-Z0-9_-]{8,128}$/);

/** Bitcoin assessment endpoints. Validation only; orchestration lives in the service. */
@Controller('v1/bitcoin')
@UseGuards(TenantGuard)
export class BitcoinController {
  constructor(@Inject('BITCOIN') private readonly service: BitcoinAssessmentService | null) {}
  private get bitcoin() {
    if (!this.service) throw new HttpException('Bitcoin collection is not configured', 404);
    return this.service;
  }
  private async assessment(tenantId: string, id: string) {
    const result = await this.bitcoin.repository.getBitcoin(tenantId, z.uuid().parse(id));
    if (!result) throw new HttpException('Assessment not found', 404);
    return result;
  }
  @Get('networks') networks() {
    return (this.service?.nodes ?? []).map(({ network, name }) => ({ network, name }));
  }
  @Post('assessments') scan(@Req() request: TenantRequest, @Body() body: unknown) {
    const key = request.headers['idempotency-key'];
    return this.bitcoin.scan(
      request.tenantId,
      BitcoinScanRequest.parse(body),
      key === undefined ? undefined : IdempotencyKey.parse(key),
      request.subject,
    );
  }
  @Get('assessments') list(@Req() request: TenantRequest) {
    return this.bitcoin.repository.listBitcoin(request.tenantId);
  }
  @Get('assessments/:id') get(@Req() request: TenantRequest, @Param('id') id: string) {
    return this.assessment(request.tenantId, id);
  }
  @Get('assessments/:id/cbom') @Header('Content-Type', CDX_MEDIA_TYPE) async cbom(
    @Req() request: TenantRequest,
    @Param('id') id: string,
  ) {
    return toCycloneDxBitcoin(await this.assessment(request.tenantId, id));
  }
}
