import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { problem, type MockRoutes } from '../../test/fetchMock';
import { SIGNED_IN, renderApp } from '../../test/renderApp';

const dsm = { id: 'a', protocol: 'tcp', port: 5001, sourceCidr: '', enabled: true, comment: 'DSM' };

function routes(overrides: MockRoutes = {}): MockRoutes {
  return {
    'GET /api/session': { body: SIGNED_IN },
    'GET /api/host-access': { body: { rules: [dsm] } },
    ...overrides,
  };
}

function save() {
  fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
}

describe('HostAccessPage', () => {
  it('enables Save changes only while the rules differ from the saved ones', async () => {
    renderApp(routes(), '/host-access');
    const port = await screen.findByRole('spinbutton', { name: 'Port, rule 1' });
    expect(port).toHaveValue(5001);
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();

    fireEvent.change(port, { target: { value: '5002' } });
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeEnabled();

    fireEvent.change(port, { target: { value: '5001' } });
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();
  });

  it('adds and removes rules and saves them', async () => {
    const saved = [
      dsm,
      {
        id: 'b',
        protocol: 'udp',
        port: 51820,
        sourceCidr: '203.0.113.0/24',
        enabled: true,
        comment: 'WG',
      },
    ];
    const { fetchMock } = renderApp(
      routes({ 'PUT /api/host-access': { body: { rules: saved } } }),
      '/host-access',
    );
    await screen.findByRole('spinbutton', { name: 'Port, rule 1' });

    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
    expect(screen.getByRole('textbox', { name: 'Source (optional), rule 2' })).toHaveAttribute(
      'placeholder',
      '203.0.113.0/24',
    );
    fireEvent.change(screen.getByRole('combobox', { name: 'Protocol, rule 2' }), {
      target: { value: 'udp' },
    });
    fireEvent.change(screen.getByRole('spinbutton', { name: 'Port, rule 2' }), {
      target: { value: '51820' },
    });
    fireEvent.change(screen.getByRole('textbox', { name: 'Source (optional), rule 2' }), {
      target: { value: '203.0.113.0/24' },
    });
    fireEvent.change(screen.getByRole('textbox', { name: 'Comment, rule 2' }), {
      target: { value: 'WG' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
    fireEvent.click(screen.getByRole('button', { name: 'Remove rule 3' }));
    save();

    expect(await screen.findByText('Rules saved and applied.')).toBeInTheDocument();
    const call = fetchMock.mock.calls.find(([, init]) => init?.method === 'PUT');
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({
      rules: [
        dsm,
        {
          id: '',
          protocol: 'udp',
          port: 51820,
          sourceCidr: '203.0.113.0/24',
          enabled: true,
          comment: 'WG',
        },
      ],
    });
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();
  });

  it('shows field errors on the matching rule', async () => {
    renderApp(
      routes({
        'PUT /api/host-access': problem(422, 'validation_failed', 'invalid', {
          fields: {
            'rules[1].port': 'must not be the web UI port',
            'rules[1].sourceCidr': 'must be an IPv4 network',
          },
        }),
      }),
      '/host-access',
    );
    await screen.findByRole('spinbutton', { name: 'Port, rule 1' });
    fireEvent.click(screen.getByRole('button', { name: 'Add rule' }));
    fireEvent.change(screen.getByRole('spinbutton', { name: 'Port, rule 2' }), {
      target: { value: '8194' },
    });
    save();

    expect(await screen.findByText('must not be the web UI port')).toBeInTheDocument();
    expect(screen.getByRole('spinbutton', { name: 'Port, rule 2' })).toHaveAttribute(
      'aria-invalid',
      'true',
    );
    expect(screen.getByRole('spinbutton', { name: 'Port, rule 1' })).not.toHaveAttribute(
      'aria-invalid',
    );
    expect(screen.getByText('must be an IPv4 network')).toBeInTheDocument();
  });

  it('shows a failed firewall apply as a danger notice and keeps the edits', async () => {
    renderApp(
      routes({
        'PUT /api/host-access': problem(
          500,
          'firewall_failed',
          'The firewall rules could not be applied.',
        ),
      }),
      '/host-access',
    );
    fireEvent.change(await screen.findByRole('spinbutton', { name: 'Port, rule 1' }), {
      target: { value: '5002' },
    });
    save();

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('The firewall rules could not be applied');
    expect(alert.closest('[data-tone]')).toHaveAttribute('data-tone', 'danger');
    expect(screen.getByRole('spinbutton', { name: 'Port, rule 1' })).toHaveValue(5002);
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeEnabled();
  });
});
