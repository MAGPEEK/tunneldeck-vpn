import { isValidElement, type ReactNode } from 'react';
import { describe, expect, it } from 'vitest';
import type { FormSchema, SchemaField } from '../../../api/profiles';
import { IPSEC_SCHEMA, WIREGUARD_SCHEMA, makeProfile } from '../../../test/fixtures';
import { IkeV1Notice, NetToNetRouteNotice } from './IpsecNotices';
import { KeyPairPanel } from './KeyPairPanel';
import { schemaAddons, type SchemaAddonContext } from './schemaAddons';

function schemaOf(...fields: SchemaField[]): FormSchema {
  return { sections: [{ key: 's', labelKey: 'x', fields }] };
}

function context(overrides: Partial<SchemaAddonContext> = {}): SchemaAddonContext {
  return {
    protocol: 'acme',
    values: {},
    secrets: {},
    profile: undefined,
    onGeneratedSecret: () => undefined,
    ...overrides,
  };
}

function typeOf(node: ReactNode): unknown {
  return isValidElement(node) ? node.type : undefined;
}

describe('schemaAddons', () => {
  it('shows the addon a field names, whatever the protocol', () => {
    const schema = schemaOf(
      { key: 'secretKey', type: 'secret', labelKey: 'k', addon: 'keyPair' },
      { key: 'phase', type: 'select', labelKey: 'p', addon: 'ikeV1Warning' },
      { key: 'topology', type: 'select', labelKey: 't', addon: 'netToNetRoute' },
    );

    const addons = schemaAddons(
      schema,
      context({ values: { phase: 'ikev1', topology: 'netToNet', remoteSubnets: ['10.1.0.0/16'] } }),
    );

    expect(Object.keys(addons).sort()).toEqual(['phase', 'secretKey', 'topology']);
    expect(typeOf(addons.secretKey)).toBe(KeyPairPanel);
    expect(typeOf(addons.phase)).toBe(IkeV1Notice);
    expect(typeOf(addons.topology)).toBe(NetToNetRouteNotice);
  });

  it('hands a generated secret back under the key of its field', () => {
    const generated: [string, string][] = [];
    const schema = schemaOf({ key: 'secretKey', type: 'secret', labelKey: 'k', addon: 'keyPair' });

    const addons = schemaAddons(
      schema,
      context({ onGeneratedSecret: (key, value) => generated.push([key, value]) }),
    );
    const panel = addons.secretKey;
    if (!isValidElement<{ onGenerated: (value: string) => void }>(panel)) {
      throw new Error('no key pair panel');
    }
    panel.props.onGenerated('PRIVATE');

    expect(generated).toEqual([['secretKey', 'PRIVATE']]);
  });

  it.each([
    ['an unknown addon id', 'confetti', { mode: 'netToNet' }],
    ['a notice whose value does not apply', 'netToNetRoute', { mode: 'hostToNet' }],
  ])('shows nothing for %s', (_name, addon, values) => {
    const schema = schemaOf({ key: 'mode', type: 'select', labelKey: 'm', addon });
    expect(schemaAddons(schema, context({ values }))).toEqual({});
  });

  it('leaves out the IKEv1 notice while the saved profile already shows the advisory', () => {
    const schema = schemaOf({ key: 'ike', type: 'select', labelKey: 'i', addon: 'ikeV1Warning' });
    const profile = makeProfile({
      advisories: [{ code: 'ikev1_aggressive', severity: 'danger' }],
    });
    expect(schemaAddons(schema, context({ values: { ike: 'ikev1' }, profile }))).toEqual({});
  });

  it.each([
    ['wireguard', WIREGUARD_SCHEMA, {}, { privateKey: KeyPairPanel }],
    [
      'ipsec',
      IPSEC_SCHEMA,
      { ikeVersion: 'ikev1', mode: 'netToNet' },
      { ikeVersion: IkeV1Notice, mode: NetToNetRouteNotice },
    ],
    ['openvpn', schemaOf({ key: 'privateKey', type: 'secret', labelKey: 'k' }), {}, {}],
  ])('shows the addons the %s schema names', (protocol, schema, values, expected) => {
    const addons = schemaAddons(schema, context({ protocol, values }));
    expect(
      Object.fromEntries(Object.entries(addons).map(([key, node]) => [key, typeOf(node)])),
    ).toEqual(expected);
  });
});
