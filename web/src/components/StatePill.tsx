import type { ReactNode } from 'react';
import styles from './StatePill.module.css';

export type StateTone = 'neutral' | 'success' | 'warning' | 'danger';

export interface StatePillProps {
  tone?: StateTone;
  dot?: boolean;
  children: ReactNode;
}

export function StatePill({ tone = 'neutral', dot = false, children }: StatePillProps) {
  return (
    <span className={`${styles.pill} ${styles[tone]}`} data-tone={tone}>
      {dot && <span className={styles.dot} aria-hidden="true" />}
      {children}
    </span>
  );
}
