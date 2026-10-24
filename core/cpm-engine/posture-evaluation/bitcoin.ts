import type {
  BitcoinAssessment,
  BitcoinObservation,
} from '../../../packages/domain-models/src/bitcoin.js';
import type { Finding } from '../../../packages/domain-models/src/index.js';

/** Confirmations below this are reported as reorganization-sensitive. */
export const SHALLOW_CONFIRMATIONS = 6;

const groupsBy = (o: BitcoinObservation, exposure: string) =>
  o.groups.filter((g) => g.keyExposure === exposure);
const total = (gs: BitcoinObservation['groups']) => ({
  count: gs.reduce((t, g) => t + g.count, 0),
  sats: gs.reduce((t, g) => t + BigInt(g.sats), 0n),
});

/** Baseline Bitcoin findings. Each states what the evidence does and does not establish. */
export function evaluateBitcoinPosture(
  o: BitcoinObservation,
  hash: string,
): BitcoinAssessment['posture'] {
  const findings: Finding[] = [];
  const add = (f: Omit<Finding, 'ruleVersion' | 'evidenceHash'>) =>
    findings.push({ ...f, ruleVersion: '1.0.0', evidenceHash: hash });
  const inScript = total(groupsBy(o, 'public-key-in-script'));
  const hashLocked = total(groupsBy(o, 'hash-locked'));
  const unknown = total(groupsBy(o, 'unknown'));
  if (inScript.count)
    add({
      ruleId: 'CV-BTC-001',
      severity: 'medium',
      confidence: 'observed',
      title: 'Public key exposed in unspent output scripts',
      rationale: `${inScript.count} unspent output(s) holding ${inScript.sats} sats lock to keys written in the output script (${groupsBy(
        o,
        'public-key-in-script',
      )
        .map((g) => g.scriptType)
        .join(
          ', ',
        )}). The elliptic-curve key is public now; this is a quantum migration dependency, not evidence of compromise.`,
    });
  if (o.revealedSpend && hashLocked.count)
    add({
      ruleId: 'CV-BTC-002',
      severity: 'medium',
      confidence: 'observed',
      title: 'Key reuse: hash-locked outputs remain after the key was revealed',
      rationale: `Confirmed transaction ${o.revealedSpend.txid} revealed ${o.revealedSpend.publicKeys.length} key(s) for this target (${o.revealedSpend.source}). ${hashLocked.count} hash-locked output(s) holding ${hashLocked.sats} sats still depend on those now-public keys.`,
    });
  if (!o.revealedSpend && hashLocked.count)
    add({
      ruleId: 'CV-BTC-003',
      severity: 'info',
      confidence: 'unknown',
      title: 'Hash-locked outputs: key exposure depends on spend history',
      rationale: `${hashLocked.count} output(s) holding ${hashLocked.sats} sats commit only to a hash. Whether the key was revealed by an earlier spend from this target is not established; supply a spending transaction to check.`,
    });
  if (unknown.count)
    add({
      ruleId: 'CV-BTC-004',
      severity: 'info',
      confidence: 'unknown',
      title: 'Non-standard output scripts',
      rationale: `${unknown.count} output(s) use scripts outside the recognized templates; their signature schemes are unknown.`,
    });
  const shallow = o.groups.filter((g) => g.minConfirmations < SHALLOW_CONFIRMATIONS);
  if (shallow.length)
    add({
      ruleId: 'CV-BTC-005',
      severity: 'info',
      confidence: 'observed',
      title: 'Outputs with few confirmations',
      rationale: `Some outputs have fewer than ${SHALLOW_CONFIRMATIONS} confirmations at block ${o.tipHash}; Bitcoin has no finality, so a reorganization could change this snapshot.`,
    });
  return { status: 'needs-review', rulepack: 'bitcoin-baseline/0.1', findings };
}
