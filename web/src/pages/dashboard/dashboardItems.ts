import { useCallback, useState } from 'react';

/** Parts of the dashboard the user can hide, in display order of the checklist. */
export const DASHBOARD_ITEMS = [
  'line',
  'tunnel',
  'address',
  'encryption',
  'lan',
  'firewall',
  'remote',
  'traffic',
] as const;

export type DashboardItem = (typeof DASHBOARD_ITEMS)[number];

/** Holds the hidden items, so items added later start visible. */
export const DASHBOARD_STORAGE_KEY = 'tunneldeck.dashboard.hidden';

function isItem(value: unknown): value is DashboardItem {
  return DASHBOARD_ITEMS.some((item) => item === value);
}

export function readHidden(): DashboardItem[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(DASHBOARD_STORAGE_KEY) ?? '[]');
    return Array.isArray(parsed) ? parsed.filter(isItem) : [];
  } catch {
    return [];
  }
}

function writeHidden(hidden: readonly DashboardItem[]): void {
  try {
    if (hidden.length === 0) {
      localStorage.removeItem(DASHBOARD_STORAGE_KEY);
    } else {
      localStorage.setItem(DASHBOARD_STORAGE_KEY, JSON.stringify(hidden));
    }
  } catch {
    // Storage blocked: the choice lasts for this page view only.
  }
}

export interface DashboardItems {
  isVisible: (item: DashboardItem) => boolean;
  setVisible: (item: DashboardItem, visible: boolean) => void;
  reset: () => void;
}

/** Which dashboard items this browser shows; all by default, stored in localStorage. */
export function useDashboardItems(): DashboardItems {
  const [hidden, setHidden] = useState<DashboardItem[]>(readHidden);

  const update = useCallback((next: DashboardItem[]) => {
    writeHidden(next);
    setHidden(next);
  }, []);

  return {
    isVisible: (item) => !hidden.includes(item),
    setVisible: (item, visible) => {
      const others = hidden.filter((other) => other !== item);
      update(visible ? others : [...others, item]);
    },
    reset: () => update([]),
  };
}
