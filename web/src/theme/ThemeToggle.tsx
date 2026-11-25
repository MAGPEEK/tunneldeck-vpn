import { Monitor, Moon, Sun } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '../components/Button';
import { applyTheme, nextTheme, readStoredTheme, storeTheme, type Theme } from './theme';

const ICONS: Record<Theme, typeof Sun> = { system: Monitor, light: Sun, dark: Moon };

export function ThemeToggle() {
  const { t } = useTranslation();
  const [theme, setTheme] = useState<Theme>(readStoredTheme);
  const Icon = ICONS[theme];

  const cycle = () => {
    const next = nextTheme(theme);
    applyTheme(next);
    storeTheme(next);
    setTheme(next);
  };

  const label = t('theme.toggle', { theme: t(`theme.${theme}`) });
  return (
    <Button variant="ghost" onClick={cycle} aria-label={label} title={label}>
      <Icon size={16} aria-hidden="true" />
    </Button>
  );
}
