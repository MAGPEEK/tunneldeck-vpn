import { useId, type ReactNode } from 'react';
import styles from './Card.module.css';

export interface CardProps {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}

export function Card({ title, actions, children }: CardProps) {
  const titleId = useId();
  const hasHeader = title !== undefined || actions !== undefined;
  return (
    <section className={styles.card} aria-labelledby={title === undefined ? undefined : titleId}>
      {hasHeader && (
        <header className={styles.header}>
          {title !== undefined && (
            <h2 id={titleId} className={styles.title}>
              {title}
            </h2>
          )}
          {actions !== undefined && <div className={styles.actions}>{actions}</div>}
        </header>
      )}
      <div className={styles.body}>{children}</div>
    </section>
  );
}
