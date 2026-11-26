import { ArrowRight } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import styles from './FirewallPage.module.css';
import type { RuleDraft } from './ruleDraft';
import { flowEndpoints, type FlowEndpoint, type RuleContext } from './ruleText';

export interface FlowStripProps {
  draft: RuleDraft;
  context: RuleContext;
}

/** `VPN · any → Local LAN · Web server`: where traffic comes from and where it goes. */
export function FlowStrip({ draft, context }: FlowStripProps) {
  const { t } = useTranslation();
  const [from, to] = flowEndpoints(t, draft, context);
  return (
    <p className={styles.flow} data-testid="flow">
      <Chip endpoint={from} />
      <ArrowRight size={14} aria-hidden="true" className={styles.flowArrow} />
      <span className="visually-hidden"> {t('firewall.flow.to')} </span>
      <Chip endpoint={to} />
    </p>
  );
}

function Chip({ endpoint }: { endpoint: FlowEndpoint }) {
  const { t } = useTranslation();
  return (
    <span className={styles.chip} data-accent={endpoint.accent || undefined}>
      <span className={styles.chipZone}>{t(`firewall.flow.${endpoint.zone}`)}</span>
      {' · '}
      <span className={styles.chipLabel}>{endpoint.label}</span>
    </span>
  );
}
