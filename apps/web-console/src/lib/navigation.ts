export const viewRoutes = {
  Overview: '/dashboard',
  Inventory: '/inventory',
  CBOM: '/cbom',
  QBOM: '/qbom',
  CPM: '/posture',
  'Trust Graph': '/trust-graph',
  Evidence: '/findings',
  Migrations: '/migrations',
  Reports: '/reports',
  Settings: '/settings',
} as const;
export type View = keyof typeof viewRoutes;

export function viewUrl(view: View, assessmentId?: string) {
  return viewRoutes[view] + (assessmentId ? `?assessment=${encodeURIComponent(assessmentId)}` : '');
}
