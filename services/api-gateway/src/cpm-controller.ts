import {
  Controller,
  UseGuards,
  Inject,
  Get,
  Post,
  Patch,
  Delete,
  Req,
  Param,
  Query,
  Body,
  HttpException,
} from '@nestjs/common';
import { z } from 'zod';
import { TenantGuard, type TenantRequest } from './tenant-guard.js';
import { CpmRepository } from '../../inventory-service/src/cpm-repository.js';
import { MonitoringStore } from '../../inventory-service/src/monitoring-store.js';
import { AssessmentService } from '../../assessment-service/src/index.js';
import {
  AssetId,
  CpmAssessRequest,
  CpmPolicy,
  PolicyAssignment,
  PolicyRef,
  MonitoringRequest,
  MonitoringUpdate,
  PageQuery,
  FindingTransition,
  MigrationRequest,
} from '../../../packages/domain-models/src/cpm.js';
import { Digest } from '../../../packages/domain-models/src/index.js';
@Controller('v1/cpm')
@UseGuards(TenantGuard)
export class CpmController {
  constructor(
    @Inject('CPM') private readonly repository: CpmRepository | null,
    @Inject('SERVICE') private readonly service: AssessmentService,
  ) {}
  get store() {
    if (!this.repository) throw new HttpException('CPM requires durable PostgreSQL storage', 503);
    return this.repository;
  }
  get jobs() {
    return new MonitoringStore(this.store.policies);
  }
  admin(r: TenantRequest) {
    if (r.role !== 'admin') throw new HttpException('Admin role required', 403);
  }
  page(query: unknown) {
    return PageQuery.parse(query);
  }
  @Post('assess') assess(@Req() r: TenantRequest, @Body() body: unknown) {
    const input = CpmAssessRequest.parse(body);
    return this.store.assess(r.tenantId, input.assessmentId, input.policy, r.subject);
  }
  @Get('posture/:assetId') async posture(@Req() r: TenantRequest, @Param('assetId') asset: string) {
    const result = await this.store.posture(r.tenantId, AssetId.parse(asset));
    if (!result) throw new HttpException('Posture not found', 404);
    return result;
  }
  @Get('history/:assetId') history(
    @Req() r: TenantRequest,
    @Param('assetId') asset: string,
    @Query() query: unknown,
  ) {
    const p = this.page(query);
    return this.store.history(r.tenantId, AssetId.parse(asset), p.limit, p.offset);
  }
  @Get('policies') policies(@Req() r: TenantRequest, @Query() query: unknown) {
    const p = this.page(query);
    return this.store.policies.list(r.tenantId, p.limit, p.offset);
  }
  @Post('policies') publish(@Req() r: TenantRequest, @Body() body: unknown) {
    this.admin(r);
    return this.store.policies.publish(r.tenantId, CpmPolicy.parse(body), r.subject);
  }
  @Patch('policies/:id') policy(
    @Req() r: TenantRequest,
    @Param('id') id: string,
    @Body() body: unknown,
  ) {
    this.admin(r);
    const input = z.object({ active: z.boolean() }).strict().parse(body);
    return this.store.policies.setActive(
      r.tenantId,
      PolicyRef.shape.id.parse(id),
      input.active,
      r.subject,
    );
  }
  @Post('assignments') assignment(@Req() r: TenantRequest, @Body() body: unknown) {
    this.admin(r);
    return this.store.policies.assign(r.tenantId, PolicyAssignment.parse(body), r.subject);
  }
  @Get('monitoring') monitoring(@Req() r: TenantRequest, @Query() query: unknown) {
    const p = this.page(query);
    return this.jobs.list(r.tenantId, p.limit, p.offset);
  }
  @Post('monitoring') schedule(@Req() r: TenantRequest, @Body() body: unknown) {
    const input = MonitoringRequest.parse(body);
    if (!this.service.chains.some((c) => c.chainId === input.input.chainId))
      throw new HttpException('Chain is not configured', 400);
    return this.jobs.create(r.tenantId, input, r.subject);
  }
  @Patch('monitoring/:id') update(
    @Req() r: TenantRequest,
    @Param('id') id: string,
    @Body() body: unknown,
  ) {
    this.admin(r);
    return this.jobs.update(
      r.tenantId,
      z.uuid().parse(id),
      MonitoringUpdate.parse(body),
      r.subject,
    );
  }
  @Delete('monitoring/:id') cancelSchedule(@Req() r: TenantRequest, @Param('id') id: string) {
    this.admin(r);
    return this.jobs.update(r.tenantId, z.uuid().parse(id), { enabled: false }, r.subject);
  }
  @Get('jobs/:id') async job(@Req() r: TenantRequest, @Param('id') id: string) {
    const result = await this.jobs.get(r.tenantId, z.uuid().parse(id));
    if (!result) throw new HttpException('Job not found', 404);
    const { lease_token: _token, ...visible } = result;
    void _token;
    return visible;
  }
  @Post('jobs/:id/cancel') cancel(@Req() r: TenantRequest, @Param('id') id: string) {
    this.admin(r);
    return this.jobs.cancel(r.tenantId, z.uuid().parse(id), r.subject);
  }
  @Get('drift') drift(@Req() r: TenantRequest, @Query() query: unknown) {
    const p = this.page(query);
    return this.store.list(r.tenantId, 'drift', p.limit, p.offset);
  }
  @Get('remediation') remediation(@Req() r: TenantRequest, @Query() query: unknown) {
    const p = this.page(query);
    return this.store.list(r.tenantId, 'remediation', p.limit, p.offset);
  }
  @Get('notifications') notifications(@Req() r: TenantRequest, @Query() query: unknown) {
    const p = this.page(query);
    return this.store.list(r.tenantId, 'notifications', p.limit, p.offset);
  }
  @Patch('findings/:snapshotId/:ruleId') transition(
    @Req() r: TenantRequest,
    @Param('snapshotId') snapshot: string,
    @Param('ruleId') rule: string,
    @Body() body: unknown,
  ) {
    this.admin(r);
    return this.store.transition(
      r.tenantId,
      Digest.parse(snapshot),
      z.string().max(80).parse(rule),
      FindingTransition.parse(body),
      r.subject,
    );
  }
  @Post('migrations/assess') migration(@Req() r: TenantRequest, @Body() body: unknown) {
    return this.store.migration(r.tenantId, MigrationRequest.parse(body), r.subject);
  }
  @Get('migrations/:id') async getMigration(@Req() r: TenantRequest, @Param('id') id: string) {
    const result = await this.store.getMigration(r.tenantId, z.uuid().parse(id));
    if (!result) throw new HttpException('Migration not found', 404);
    return result.document;
  }
  @Post('migrations/:id/verify') async verify(
    @Req() r: TenantRequest,
    @Param('id') id: string,
    @Body() body: unknown,
  ) {
    const input = z.object({ assessmentId: z.uuid() }).strict().parse(body);
    const parent = await this.store.getMigration(r.tenantId, z.uuid().parse(id));
    if (!parent) throw new HttpException('Migration not found', 404);
    return this.store.migration(
      r.tenantId,
      { ...parent.request, assessmentId: input.assessmentId },
      r.subject,
      id,
    );
  }
}
