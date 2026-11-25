import type { ReactNode } from 'react';
import styles from './Page.module.css';

export interface PageProps {
  title: ReactNode;
  children: ReactNode;
}

export function Page({ title, children }: PageProps) {
  return (
    <div className={styles.page}>
      <h1 className={styles.title}>{title}</h1>
      {children}
    </div>
  );
}
