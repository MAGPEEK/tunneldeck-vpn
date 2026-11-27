import { useId, type KeyboardEvent, type ReactNode } from 'react';
import styles from './Tabs.module.css';

export interface TabItem {
  id: string;
  label: ReactNode;
}

export interface TabsProps {
  /** Accessible name for the tab list. */
  label: string;
  tabs: TabItem[];
  /** The id of the selected tab. */
  active: string;
  onChange: (id: string) => void;
  /** The content of the selected tab's panel. */
  children: ReactNode;
}

/**
 * An accessible tab list (WAI-ARIA tabs): roving focus, arrow-key navigation and
 * a single rendered panel for the active tab. The caller decides what the panel
 * holds, so only the active tab's content is mounted.
 */
export function Tabs({ label, tabs, active, onChange, children }: TabsProps) {
  const base = useId();
  const tabId = (id: string) => `${base}-tab-${id}`;
  const panelId = (id: string) => `${base}-panel-${id}`;
  const index = Math.max(
    0,
    tabs.findIndex((tab) => tab.id === active),
  );

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    let next: number;
    switch (event.key) {
      case 'ArrowRight':
      case 'ArrowDown':
        next = (index + 1) % tabs.length;
        break;
      case 'ArrowLeft':
      case 'ArrowUp':
        next = (index - 1 + tabs.length) % tabs.length;
        break;
      case 'Home':
        next = 0;
        break;
      case 'End':
        next = tabs.length - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    const target = tabs[next];
    if (target) {
      onChange(target.id);
      document.getElementById(tabId(target.id))?.focus();
    }
  };

  return (
    <div className={styles.tabs}>
      <div role="tablist" aria-label={label} className={styles.tablist} onKeyDown={onKeyDown}>
        {tabs.map((tab) => {
          const selected = tab.id === active;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              id={tabId(tab.id)}
              aria-selected={selected}
              aria-controls={panelId(tab.id)}
              tabIndex={selected ? 0 : -1}
              className={selected ? `${styles.tab} ${styles.selected}` : styles.tab}
              onClick={() => onChange(tab.id)}
            >
              {tab.label}
            </button>
          );
        })}
      </div>
      <div role="tabpanel" id={panelId(active)} aria-labelledby={tabId(active)}>
        {children}
      </div>
    </div>
  );
}
