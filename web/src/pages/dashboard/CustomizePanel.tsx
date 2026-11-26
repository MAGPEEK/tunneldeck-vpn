import { SlidersHorizontal } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button } from '../../components/Button';
import styles from './CustomizePanel.module.css';
import { DASHBOARD_ITEMS, type DashboardItems } from './dashboardItems';

export interface CustomizeToggleProps {
  open: boolean;
  panelId: string;
  onToggle: (open: boolean) => void;
}

export function CustomizeToggle({ open, panelId, onToggle }: CustomizeToggleProps) {
  const { t } = useTranslation();
  return (
    <Button
      variant="ghost"
      size="small"
      icon={<SlidersHorizontal size={14} aria-hidden="true" />}
      aria-expanded={open}
      aria-controls={panelId}
      onClick={() => onToggle(!open)}
    >
      {t('dashboard.customize.open')}
    </Button>
  );
}

/** Checklist of the items the dashboard shows, with a reset to all. */
export function CustomizePanel({ id, items }: { id: string; items: DashboardItems }) {
  const { t } = useTranslation();
  return (
    <fieldset id={id} className={styles.panel}>
      <legend className={styles.legend}>{t('dashboard.customize.legend')}</legend>
      <div className={styles.checks}>
        {DASHBOARD_ITEMS.map((item) => (
          <label key={item} className={styles.check}>
            <input
              type="checkbox"
              checked={items.isVisible(item)}
              onChange={(event) => items.setVisible(item, event.currentTarget.checked)}
            />
            {t(`dashboard.customize.item.${item}`)}
          </label>
        ))}
      </div>
      <button type="button" className={styles.reset} onClick={items.reset}>
        {t('dashboard.customize.reset')}
      </button>
    </fieldset>
  );
}
