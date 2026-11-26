import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { FirewallSettings, ProtectionSupport } from '../../api/firewall';
import { i18n } from '../../i18n';
import { ProtectionCard } from './ProtectionCard';

const SETTINGS: FirewallSettings = {
  dropInvalid: true,
  mssClamp: true,
  synFloodProtection: true,
  pingLimit: true,
};

const FULL: ProtectionSupport = {
  synFlood: 'full',
  ping: 'full',
  mssClamp: 'full',
  ruleCounters: true,
};

describe('ProtectionCard', () => {
  it('shows no note while the kernel supports every protection', () => {
    render(<ProtectionCard settings={SETTINGS} support={FULL} onChange={() => {}} />);
    expect(screen.getAllByRole('switch')).toHaveLength(4);
    expect(screen.queryByText('Global limit only')).not.toBeInTheDocument();
    expect(screen.queryByText('Not available on this system')).not.toBeInTheDocument();
  });

  it('notes a global limit and a missing protection next to their switches, which stay usable', () => {
    const onChange = vi.fn();
    render(
      <ProtectionCard
        settings={SETTINGS}
        support={{ synFlood: 'global', ping: 'none', mssClamp: 'none', ruleCounters: false }}
        onChange={onChange}
      />,
    );
    const synFlood = screen.getByRole('switch', { name: 'SYN flood protection' });
    expect(synFlood).toHaveAccessibleDescription(/Global limit only/);
    expect(screen.getByRole('switch', { name: 'Ping limit' })).toHaveAccessibleDescription(
      /Not available on this system/,
    );
    expect(screen.getByRole('switch', { name: 'Clamp TCP MSS' })).toHaveAccessibleDescription(
      /Not available on this system/,
    );
    expect(
      screen.getByRole('switch', { name: 'Drop invalid packets' }),
    ).not.toHaveAccessibleDescription(/available|limit only/);
    fireEvent.click(synFlood);
    expect(onChange).toHaveBeenCalledWith({ ...SETTINGS, synFloodProtection: false });
  });

  it('shows the notes in German', async () => {
    await i18n.changeLanguage('de');
    render(
      <ProtectionCard
        settings={SETTINGS}
        support={{ synFlood: 'global', ping: 'full', mssClamp: 'none', ruleCounters: true }}
        onChange={() => {}}
      />,
    );
    expect(screen.getAllByText('Nur globales Limit')).toHaveLength(1);
    expect(screen.getByText('Auf diesem System nicht verfügbar')).toBeInTheDocument();
  });

  it('shows no note without support information', () => {
    render(<ProtectionCard settings={SETTINGS} onChange={() => {}} />);
    expect(screen.queryByText('Not available on this system')).not.toBeInTheDocument();
  });
});
