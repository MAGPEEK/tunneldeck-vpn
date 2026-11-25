import { BrickWall, LayoutDashboard, List, LogOut, Settings, ShieldCheck } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { NavLink, Outlet } from 'react-router';
import { Button } from '../components/Button';
import { LanguageSwitch } from '../i18n/LanguageSwitch';
import { useLogout } from '../session/useSession';
import { ThemeToggle } from '../theme/ThemeToggle';
import styles from './AppShell.module.css';

const NAV_ITEMS = [
  { to: '/', label: 'nav.dashboard', Icon: LayoutDashboard },
  { to: '/profiles', label: 'nav.profiles', Icon: List },
  { to: '/firewall', label: 'nav.firewall', Icon: BrickWall },
  { to: '/system', label: 'nav.system', Icon: Settings },
] as const;

function navLinkClass({ isActive }: { isActive: boolean }): string | undefined {
  return isActive ? `${styles.link} ${styles.active}` : styles.link;
}

function SignOutButton() {
  const { t } = useTranslation();
  const logout = useLogout();
  return (
    <Button
      variant="ghost"
      icon={<LogOut size={16} aria-hidden="true" />}
      loading={logout.isPending}
      onClick={() => logout.mutate()}
    >
      {t('session.signOut')}
    </Button>
  );
}

export function AppShell() {
  const { t } = useTranslation();
  return (
    <div className={styles.shell}>
      <aside className={styles.sidebar}>
        <p className={styles.brand}>
          <ShieldCheck size={20} aria-hidden="true" />
          {t('app.name')}
        </p>
        <nav aria-label={t('nav.label')} className={styles.nav}>
          <ul className={styles.navList}>
            {NAV_ITEMS.map(({ to, label, Icon }) => (
              <li key={to}>
                <NavLink to={to} end={to === '/'} className={navLinkClass}>
                  <Icon size={16} aria-hidden="true" />
                  {t(label)}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
        <div className={styles.footer}>
          <LanguageSwitch />
          <ThemeToggle />
          <SignOutButton />
        </div>
      </aside>
      <main className={styles.content}>
        <Outlet />
      </main>
    </div>
  );
}
