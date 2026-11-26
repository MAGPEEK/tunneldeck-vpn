import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { FormSchema, Profile } from '../../../api/profiles';
import { OPENVPN_SCHEMA } from '../../../test/fixtures';
import { SchemaForm } from './SchemaForm';
import {
  initialSecrets,
  initialValues,
  schemaErrorKey,
  toRequestPart,
  type SchemaRequestPart,
} from './schemaValues';

interface HarnessProps {
  schema?: FormSchema;
  settings?: Profile['settings'];
  stored?: Profile['secrets'];
  draftSecrets?: Record<string, string>;
  errors?: Record<string, string>;
  onSubmit: (part: SchemaRequestPart) => void;
}

function Harness({
  schema = OPENVPN_SCHEMA,
  settings,
  stored,
  draftSecrets,
  errors = {},
  onSubmit,
}: HarnessProps) {
  const [values, setValues] = useState(() => initialValues(schema, settings));
  const [secrets, setSecrets] = useState(() => initialSecrets(schema, stored, draftSecrets));
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit(toRequestPart(schema, values, secrets));
      }}
    >
      <SchemaForm
        schema={schema}
        values={values}
        secrets={secrets}
        errors={errors}
        onValuesChange={setValues}
        onSecretsChange={setSecrets}
      />
      <button type="submit">Submit</button>
    </form>
  );
}

function renderHarness(props: Omit<HarnessProps, 'onSubmit'> = {}) {
  let submitted: SchemaRequestPart | undefined;
  render(<Harness {...props} onSubmit={(part) => (submitted = part)} />);
  return {
    submit: () => {
      fireEvent.submit(
        screen.getByRole('button', { name: 'Submit' }).closest('form') as HTMLFormElement,
      );
      if (!submitted) throw new Error('form was not submitted');
      return submitted;
    },
  };
}

const SECRET_SCHEMA: FormSchema = {
  sections: [
    {
      key: 's',
      labelKey: 'openvpn.section.authentication',
      fields: [
        { key: 'password', type: 'secret', labelKey: 'openvpn.password', required: true },
        { key: 'tlsAuthKey', type: 'secret', labelKey: 'openvpn.tlsAuthKey', multiline: true },
      ],
    },
  ],
};

describe('SchemaForm', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders sections with translated labels and applies defaults', () => {
    const { submit } = renderHarness();

    expect(screen.getByRole('heading', { name: 'Server' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Advanced' })).toBeInTheDocument();
    expect(screen.getByLabelText('Server address')).toHaveAttribute(
      'placeholder',
      'vpn.example.com',
    );
    expect(screen.getByLabelText('Port')).toHaveValue(1194);
    expect(screen.getByLabelText('Transport')).toHaveValue('udp');
    expect(screen.getByLabelText('Retry name resolution (seconds or infinite)')).toHaveValue(
      'infinite',
    );
    expect(
      screen.getByRole('checkbox', {
        name: 'Check that the server certificate is issued for a server',
      }),
    ).toBeChecked();

    expect(submit().settings).toEqual({
      port: 1194,
      proto: 'udp',
      authMode: 'password',
      compression: 'none',
      verifyServerCertUsage: true,
      resolveRetry: 'infinite',
    });
  });

  it('shows the key direction only while a TLS auth key is set', () => {
    const { submit } = renderHarness();
    expect(screen.queryByLabelText('Key direction')).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('TLS auth key'), { target: { value: 'KEY' } });

    expect(screen.getByLabelText('Key direction')).toHaveValue('1');
    expect(submit().settings.keyDirection).toBe('1');

    fireEvent.change(screen.getByLabelText('TLS auth key'), { target: { value: '' } });
    expect(screen.queryByLabelText('Key direction')).not.toBeInTheDocument();
  });

  it('shows a field with a secret condition while the stored secret is kept', () => {
    const schema: FormSchema = {
      sections: [
        {
          key: 's',
          labelKey: 'openvpn.section.encryption',
          fields: [
            { key: 'tlsAuthKey', type: 'secret', labelKey: 'openvpn.tlsAuthKey', multiline: true },
            {
              key: 'dependent',
              type: 'text',
              labelKey: 'openvpn.keyDirection',
              visibleWhen: { secret: 'tlsAuthKey' },
            },
          ],
        },
      ],
    };
    const { submit } = renderHarness({
      schema,
      settings: { dependent: 'x' },
      stored: { tlsAuthKey: { hasValue: true } },
    });
    expect(screen.getByLabelText('Key direction')).toHaveValue('x');
    expect(submit().settings).toEqual({ dependent: 'x' });

    fireEvent.click(
      within(screen.getByRole('group', { name: 'TLS auth key' })).getByRole('button', {
        name: 'Remove',
      }),
    );

    expect(screen.queryByLabelText('Key direction')).not.toBeInTheDocument();
  });

  it('sends text, number, select, textarea and bool values with their JSON types', () => {
    const { submit } = renderHarness();

    fireEvent.change(screen.getByLabelText('Server address'), {
      target: { value: 'publicip20.mdex.de' },
    });
    fireEvent.change(screen.getByLabelText('Port'), { target: { value: '1195' } });
    fireEvent.change(screen.getByLabelText('Transport'), { target: { value: 'tcp' } });
    fireEvent.change(screen.getByLabelText('CA certificate'), { target: { value: 'PEM' } });
    fireEvent.click(
      screen.getByRole('checkbox', {
        name: 'Check that the server certificate is issued for a server',
      }),
    );

    const { settings } = submit();
    expect(settings.remoteHost).toBe('publicip20.mdex.de');
    expect(settings.port).toBe(1195);
    expect(settings.proto).toBe('tcp');
    expect(settings.caCert).toBe('PEM');
    expect(settings.verifyServerCertUsage).toBe(false);
  });

  it('shows fields only while visibleWhen matches and leaves hidden ones out', () => {
    const { submit } = renderHarness({ settings: { username: 'alice' } });
    expect(screen.getByLabelText('Username')).toBeInTheDocument();
    expect(screen.queryByLabelText('Client certificate')).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Sign-in method'), { target: { value: 'certificate' } });

    expect(screen.queryByLabelText('Username')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Password')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Client certificate')).toBeInTheDocument();
    expect(screen.getByLabelText('Client key').tagName).toBe('TEXTAREA');
    expect(screen.getByLabelText('Key passphrase')).toHaveAttribute('type', 'password');
    expect(submit().settings).not.toHaveProperty('username');
  });

  it('adds and removes extra option rows', () => {
    const { submit } = renderHarness({ settings: { extraOptions: ['tun-mtu 1500'] } });
    const list = screen.getByRole('group', { name: 'Extra options' });
    expect(within(list).getByRole('textbox', { name: 'Extra options, line 1' })).toHaveValue(
      'tun-mtu 1500',
    );

    fireEvent.click(within(list).getByRole('button', { name: 'Add line' }));
    fireEvent.change(within(list).getByRole('textbox', { name: 'Extra options, line 2' }), {
      target: { value: 'fragment 1448' },
    });
    fireEvent.click(within(list).getByRole('button', { name: 'Add line' }));
    fireEvent.change(within(list).getByRole('textbox', { name: 'Extra options, line 3' }), {
      target: { value: 'mssfix' },
    });
    expect(within(list).getAllByRole('button', { name: 'Add line' })).toHaveLength(1);

    fireEvent.click(within(list).getByRole('button', { name: 'Remove line 1' }));

    expect(submit().settings.extraOptions).toEqual(['fragment 1448', 'mssfix']);
  });

  it('drops blank extra option rows and omits an empty list', () => {
    const { submit } = renderHarness();
    const list = screen.getByRole('group', { name: 'Extra options' });
    fireEvent.click(within(list).getByRole('button', { name: 'Add line' }));
    expect(submit().settings).not.toHaveProperty('extraOptions');
  });

  it('sends a new secret typed into a password input', () => {
    const { submit } = renderHarness({ schema: SECRET_SCHEMA });
    const input = screen.getByLabelText('Password');
    expect(input).toHaveAttribute('type', 'password');
    expect(screen.getByLabelText('TLS auth key').tagName).toBe('TEXTAREA');

    fireEvent.change(input, { target: { value: 's3cret' } });

    expect(submit()).toEqual({ settings: {}, secrets: { password: 's3cret' }, clearSecrets: [] });
  });

  it('keeps a stored secret unless it is replaced', () => {
    const { submit } = renderHarness({
      schema: SECRET_SCHEMA,
      stored: { password: { hasValue: true } },
    });
    const group = screen.getByRole('group', { name: 'Password' });
    expect(within(group).getByText('Stored')).toBeInTheDocument();
    expect(within(group).queryByRole('button', { name: 'Remove' })).not.toBeInTheDocument();
    expect(submit()).toEqual({ settings: {}, secrets: {}, clearSecrets: [] });

    fireEvent.click(within(group).getByRole('button', { name: 'Replace' }));
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'new-one' } });

    expect(submit().secrets).toEqual({ password: 'new-one' });
  });

  it('returns to the stored value from replace mode', () => {
    const { submit } = renderHarness({
      schema: SECRET_SCHEMA,
      stored: { password: { hasValue: true } },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Replace' }));
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'typo' } });
    fireEvent.click(screen.getByRole('button', { name: 'Keep stored value' }));

    expect(screen.getByText('Stored')).toBeInTheDocument();
    expect(submit().secrets).toEqual({});
  });

  it('clears an optional stored secret and can undo it', () => {
    const { submit } = renderHarness({
      schema: SECRET_SCHEMA,
      stored: { tlsAuthKey: { hasValue: true } },
    });
    const group = screen.getByRole('group', { name: 'TLS auth key' });

    fireEvent.click(within(group).getByRole('button', { name: 'Remove' }));
    expect(within(group).getByText('Will be removed on save')).toBeInTheDocument();
    expect(submit().clearSecrets).toEqual(['tlsAuthKey']);

    fireEvent.click(within(group).getByRole('button', { name: 'Undo' }));
    expect(submit().clearSecrets).toEqual([]);
  });

  it('pre-fills secrets from an import draft', () => {
    const { submit } = renderHarness({
      schema: SECRET_SCHEMA,
      draftSecrets: { tlsAuthKey: 'KEY' },
    });
    expect(screen.getByLabelText('TLS auth key')).toHaveValue('KEY');
    expect(submit().secrets).toEqual({ tlsAuthKey: 'KEY' });
  });

  it('reads a chosen PKCS#12 file and sends it base64-encoded', async () => {
    const { submit } = renderHarness({ settings: { authMode: 'certificate' } });
    const bytes = new Uint8Array([0x30, 0x82, 0x01, 0xff, 0x02, 0x01, 0x03]);
    const file = new File([bytes], 'client.p12', { type: 'application/x-pkcs12' });

    fireEvent.change(
      screen.getByLabelText(
        'Load PKCS#12 file (instead of client certificate and key) from a file',
      ),
      { target: { files: [file] } },
    );

    const textarea = screen.getByLabelText('PKCS#12 file (instead of client certificate and key)');
    await waitFor(() => expect(textarea).toHaveValue('MIIB/wIBAw=='));
    expect(submit().secrets).toEqual({ pkcs12: 'MIIB/wIBAw==' });
  });

  it('reads the file by the field encoding, not by the key', async () => {
    const schema: FormSchema = {
      sections: [
        {
          key: 's',
          labelKey: 'openvpn.section.authentication',
          fields: [
            {
              key: 'bundle',
              type: 'secret',
              labelKey: 'openvpn.tlsCryptKey',
              multiline: true,
              encoding: 'base64',
            },
            { key: 'tlsAuthKey', type: 'secret', labelKey: 'openvpn.tlsAuthKey', multiline: true },
          ],
        },
      ],
    };
    const { submit } = renderHarness({ schema });

    fireEvent.change(screen.getByLabelText('Load TLS crypt key from a file'), {
      target: { files: [new File([new Uint8Array([1, 2, 3])], 'x.bin')] },
    });
    await waitFor(() => expect(screen.getByLabelText('TLS crypt key')).toHaveValue('AQID'));
    const key = '-----BEGIN KEY-----\n';
    fireEvent.change(screen.getByLabelText('Load TLS auth key from a file'), {
      target: { files: [new File([key], 'ta.key')] },
    });
    await waitFor(() => expect(screen.getByLabelText('TLS crypt key')).toHaveValue('AQID'));
    await waitFor(() => expect(screen.getByLabelText('TLS auth key')).toHaveValue(key));
    expect(submit().secrets).toEqual({ bundle: 'AQID', tlsAuthKey: key });
  });

  it('loads a PEM file into a text area', async () => {
    const { submit } = renderHarness({ settings: { authMode: 'certificate' } });
    const pem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';

    fireEvent.change(screen.getByLabelText('Load CA certificate from a file'), {
      target: { files: [new File([pem], 'ca.crt')] },
    });

    await waitFor(() => expect(screen.getByLabelText('CA certificate')).toHaveValue(pem));
    expect(submit().settings.caCert).toBe(pem);
  });

  it('keeps both values when two files finish loading at the same time', async () => {
    const { submit } = renderHarness({ settings: { authMode: 'certificate' } });
    const ca = '-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n';
    const cert = '-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----\n';
    const key = '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n';
    const ta = '-----BEGIN OpenVPN Static key V1-----\n';

    // All four reads are in flight before the first one settles.
    fireEvent.change(screen.getByLabelText('Load CA certificate from a file'), {
      target: { files: [new File([ca], 'ca.crt')] },
    });
    fireEvent.change(screen.getByLabelText('Load Client certificate from a file'), {
      target: { files: [new File([cert], 'client.crt')] },
    });
    fireEvent.change(screen.getByLabelText('Load Client key from a file'), {
      target: { files: [new File([key], 'client.key')] },
    });
    fireEvent.change(screen.getByLabelText('Load TLS auth key from a file'), {
      target: { files: [new File([ta], 'ta.key')] },
    });

    await waitFor(() => expect(screen.getByLabelText('TLS auth key')).toHaveValue(ta));
    expect(screen.getByLabelText('CA certificate')).toHaveValue(ca);
    expect(screen.getByLabelText('Client certificate')).toHaveValue(cert);
    expect(screen.getByLabelText('Client key')).toHaveValue(key);
    const part = submit();
    expect(part.settings).toMatchObject({ caCert: ca, clientCert: cert });
    expect(part.secrets).toEqual({ clientKey: key, tlsAuthKey: ta });
  });

  it('shows a field error when the chosen file cannot be read', async () => {
    renderHarness({ schema: SECRET_SCHEMA });
    const file = new File(['x'], 'ta.key');
    vi.spyOn(file, 'text').mockRejectedValue(new DOMException('gone', 'NotReadableError'));

    fireEvent.change(screen.getByLabelText('Load TLS auth key from a file'), {
      target: { files: [file] },
    });

    const textarea = screen.getByLabelText('TLS auth key');
    await waitFor(() =>
      expect(textarea).toHaveAccessibleDescription(
        expect.stringContaining('The file could not be read.'),
      ),
    );
    expect(textarea).toHaveAttribute('aria-invalid', 'true');
    expect(textarea).toHaveValue('');

    fireEvent.change(textarea, { target: { value: 'typed' } });
    expect(screen.queryByText('The file could not be read.')).not.toBeInTheDocument();
  });

  it('refuses a file larger than 512 KiB without reading it', async () => {
    renderHarness({ settings: { authMode: 'certificate' } });
    const file = new File(['x'], 'huge.crt');
    Object.defineProperty(file, 'size', { value: 512 * 1024 + 1 });
    const read = vi.spyOn(file, 'text');

    fireEvent.change(screen.getByLabelText('Load CA certificate from a file'), {
      target: { files: [file] },
    });

    expect(await screen.findByText('The file must be at most 512 KiB.')).toBeInTheDocument();
    expect(screen.getByLabelText('CA certificate')).toHaveValue('');
    expect(read).not.toHaveBeenCalled();
  });

  it('clears the file error once a file was read', async () => {
    renderHarness({ settings: { authMode: 'certificate' } });
    const loader = screen.getByLabelText('Load CA certificate from a file');
    const huge = new File(['x'], 'huge.crt');
    Object.defineProperty(huge, 'size', { value: 600 * 1024 });
    fireEvent.change(loader, { target: { files: [huge] } });
    await screen.findByText('The file must be at most 512 KiB.');

    fireEvent.change(loader, { target: { files: [new File(['PEM'], 'ca.crt')] } });

    await waitFor(() => expect(screen.getByLabelText('CA certificate')).toHaveValue('PEM'));
    expect(screen.queryByText('The file must be at most 512 KiB.')).not.toBeInTheDocument();
  });

  it('clears the picker so that choosing the same file again reads it again', async () => {
    renderHarness({ schema: SECRET_SCHEMA });
    const file = new File(['KEY'], 'ta.key');
    const loader = screen.getByLabelText('Load TLS auth key from a file');
    const textarea = screen.getByLabelText('TLS auth key');
    // A browser fires no change event for the same file unless the value was cleared.
    const setValue = vi.fn();
    Object.defineProperty(loader, 'value', { configurable: true, get: () => '', set: setValue });

    fireEvent.change(loader, { target: { files: [file] } });
    await waitFor(() => expect(textarea).toHaveValue('KEY'));
    expect(setValue).toHaveBeenCalledWith('');

    fireEvent.change(textarea, { target: { value: 'edited' } });
    fireEvent.change(loader, { target: { files: [file] } });
    await waitFor(() => expect(textarea).toHaveValue('KEY'));
  });

  it('labels the remote networks list', () => {
    renderHarness();
    expect(
      screen.getByRole('group', { name: 'Remote networks (behind the VPN, one CIDR per line)' }),
    ).toBeInTheDocument();
  });

  it('shows errors under the matching field', () => {
    renderHarness({
      errors: { remoteHost: 'is required', extraOptions: 'line 2: up is not allowed' },
    });
    expect(screen.getByLabelText('Server address')).toHaveAccessibleDescription('is required');
    expect(screen.getByText('line 2: up is not allowed')).toBeInTheDocument();
  });
});

describe('schemaErrorKey', () => {
  it.each([
    ['remoteHost', 'remoteHost'],
    ['settings.port', 'port'],
    ['secrets.password', 'password'],
    ['name', 'name'],
  ])('maps %s to %s', (input, expected) => {
    expect(schemaErrorKey(input)).toBe(expected);
  });
});
