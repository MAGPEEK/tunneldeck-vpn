import { useId, useRef, type KeyboardEvent, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { FirewallDirection } from '../../api/firewall';
import styles from './FirewallPage.module.css';

const DIRECTIONS: FirewallDirection[] = ['inbound', 'outbound'];

export interface DirectionTabsProps {
  selected: FirewallDirection;
  onSelect: (direction: FirewallDirection) => void;
  /** The panel of the selected tab. */
  children: ReactNode;
}

/** A WAI-ARIA tablist: arrow keys, Home and End move between the two directions. */
export function DirectionTabs({ selected, onSelect, children }: DirectionTabsProps) {
  const { t } = useTranslation();
  const id = useId();
  const tabs = useRef<Partial<Record<FirewallDirection, HTMLButtonElement | null>>>({});

  const onKeyDown = (event: KeyboardEvent) => {
    const index = DIRECTIONS.indexOf(selected);
    const target = {
      ArrowLeft: DIRECTIONS[(index + DIRECTIONS.length - 1) % DIRECTIONS.length],
      ArrowRight: DIRECTIONS[(index + 1) % DIRECTIONS.length],
      Home: DIRECTIONS[0],
      End: DIRECTIONS[DIRECTIONS.length - 1],
    }[event.key];
    if (target !== undefined) {
      event.preventDefault();
      onSelect(target);
      tabs.current[target]?.focus();
    }
  };

  return (
    <>
      <div
        role="tablist"
        aria-label={t('firewall.tabs.label')}
        className={styles.tablist}
        onKeyDown={onKeyDown}
      >
        {DIRECTIONS.map((direction) => (
          <button
            key={direction}
            ref={(element) => {
              tabs.current[direction] = element;
            }}
            type="button"
            role="tab"
            id={`${id}-${direction}-tab`}
            aria-selected={direction === selected}
            aria-controls={`${id}-panel`}
            tabIndex={direction === selected ? 0 : -1}
            className={styles.tab}
            onClick={() => onSelect(direction)}
          >
            {t(`firewall.tabs.${direction}`)}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`${id}-panel`} aria-labelledby={`${id}-${selected}-tab`}>
        {children}
      </div>
    </>
  );
}
