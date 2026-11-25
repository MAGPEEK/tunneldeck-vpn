import type { HostAccessRule, Transport } from '../../api/hostAccess';

/** A rule while it is edited; the port stays text until saved. */
export interface RuleRow {
  key: string;
  id: string;
  protocol: Transport;
  port: string;
  sourceCidr: string;
  enabled: boolean;
  comment: string;
}

let nextKey = 0;

function rowKey(): string {
  nextKey += 1;
  return `rule-${nextKey}`;
}

export function toRows(rules: readonly HostAccessRule[]): RuleRow[] {
  return rules.map((rule) => ({ ...rule, key: rowKey(), port: String(rule.port) }));
}

export function newRow(): RuleRow {
  return {
    key: rowKey(),
    id: '',
    protocol: 'tcp',
    port: '',
    sourceCidr: '',
    enabled: true,
    comment: '',
  };
}

/** The rules as the API takes them. An empty or invalid port becomes 0 so the server reports it. */
export function toRules(rows: readonly RuleRow[]): HostAccessRule[] {
  return rows.map((row) => {
    const port = Number(row.port.trim());
    return {
      id: row.id,
      protocol: row.protocol,
      port: row.port.trim() === '' || !Number.isInteger(port) ? 0 : port,
      sourceCidr: row.sourceCidr.trim(),
      enabled: row.enabled,
      comment: row.comment.trim(),
    };
  });
}

export function rowsDiffer(rows: readonly RuleRow[], saved: readonly HostAccessRule[]): boolean {
  return JSON.stringify(toRules(rows)) !== JSON.stringify(toRules(toRows(saved)));
}

/** Field errors for row `index` from keys such as `rules[0].port`. */
export function rowErrors(fields: Record<string, string>, index: number): Record<string, string> {
  const prefix = `rules[${index}].`;
  return Object.fromEntries(
    Object.entries(fields)
      .filter(([key]) => key.startsWith(prefix))
      .map(([key, message]) => [key.slice(prefix.length), message]),
  );
}
