import type { ReactNode } from 'react';
import styles from './StatePill.module.css';

export type StateTone = 'neutral' | 'success' | 'warning' | 'danger';

/** A pill's tone: a state, or accent for something switched on that is no state. */
export type PillTone = StateTone | 'accent';

export interface StatePillProps {
  tone?: PillTone;
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
