import { Info, OctagonExclamationPoint, TriangleExclamationPoint } from 'lucide-react';
import type { ReactNode } from 'react';
import styles from './Notice.module.css';

export type NoticeTone = 'info' | 'warning' | 'danger';

export interface NoticeProps {
  tone?: NoticeTone;
  title?: ReactNode;
  children?: ReactNode;
  /** `alert` for errors the user just caused; `status` for results; none for static text. */
  role?: 'alert' | 'status';
  actions?: ReactNode;
}

const ICONS = {
  info: Info,
  warning: TriangleExclamationPoint,
  danger: OctagonExclamationPoint,
} as const;

export function Notice({ tone = 'info', title, children, role, actions }: NoticeProps) {
  const Icon = ICONS[tone];
  return (
    <div className={`${styles.notice} ${styles[tone]}`} role={role} data-tone={tone}>
      <Icon size={16} aria-hidden="true" className={styles.icon} />
      <div className={styles.content}>
        {title !== undefined && <p className={styles.title}>{title}</p>}
        {children}
        {actions !== undefined && <div className={styles.actions}>{actions}</div>}
      </div>
    </div>
  );
}
