import type { ReactNode } from 'react';
import styles from './Page.module.css';

export interface PageProps {
  title: ReactNode;
  /** Buttons next to the title. */
  actions?: ReactNode;
  children: ReactNode;
}

export function Page({ title, actions, children }: PageProps) {
  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>{title}</h1>
        {actions !== undefined && <div className={styles.actions}>{actions}</div>}
      </div>
      {children}
    </div>
  );
}
