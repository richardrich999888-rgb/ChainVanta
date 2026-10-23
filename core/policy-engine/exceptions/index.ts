export type FindingState =
  | 'open'
  | 'acknowledged'
  | 'in_remediation'
  | 'pending_verification'
  | 'resolved'
  | 'excepted'
  | 'administratively_closed';
export function effectiveStatus(
  event: { status: string; expires_at?: string | Date | null },
  now = new Date(),
): FindingState {
  if (event.status === 'excepted' && (!event.expires_at || new Date(event.expires_at) <= now))
    return 'open';
  return event.status as FindingState;
}
export function allowedTransition(from: FindingState, to: FindingState): boolean {
  if (to === 'resolved') return false; // Only a later, comparable satisfied rule can resolve technically.
  if (to === 'open') return true;
  if (to === 'excepted' || to === 'administratively_closed') return from !== 'resolved';
  return (
    {
      open: ['acknowledged'],
      acknowledged: ['in_remediation'],
      in_remediation: ['pending_verification'],
      pending_verification: ['in_remediation'],
      excepted: ['acknowledged'],
      resolved: [],
      administratively_closed: ['acknowledged'],
    } as Record<FindingState, string[]>
  )[from].includes(to);
}
