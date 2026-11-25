import { ShieldCheck } from 'lucide-react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import styles from './AuthLayout.module.css';

export interface AuthLayoutProps {
  title: ReactNode;
  children: ReactNode;
}

export function AuthLayout({ title, children }: AuthLayoutProps) {
  const { t } = useTranslation();
  return (
    <main className={styles.screen}>
      <div className={styles.column}>
        <p className={styles.brand}>
          <ShieldCheck size={20} aria-hidden="true" />
          {t('app.name')}
        </p>
        <div className={styles.card}>
          <h1 className={styles.title}>{title}</h1>
          {children}
        </div>
      </div>
    </main>
  );
}
