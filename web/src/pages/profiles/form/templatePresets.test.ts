import { describe, expect, it } from 'vitest';
import { IPSEC_SCHEMA, OPENVPN_SCHEMA } from '../../../test/fixtures';
import { initialValues } from '../schema/schemaValues';
import { applyTemplate, changedTemplate, forceTemplate, templateFields } from './templatePresets';

const choose = (values: ReturnType<typeof initialValues>, template: string) => {
  const after = { ...values, template };
  const choice = changedTemplate(IPSEC_SCHEMA, values, after);
  if (!choice) throw new Error('no template change');
  return choice;
};

describe('templateFields', () => {
  it.each([
    ['ipsec', IPSEC_SCHEMA, ['template']],
    ['openvpn', OPENVPN_SCHEMA, []],
  ])('finds the select fields with presets of %s', (_name, schema, keys) => {
    expect(templateFields(schema).map((field) => field.key)).toEqual(keys);
  });
});

describe('changedTemplate', () => {
  it('is undefined when no template value changed', () => {
    const values = initialValues(IPSEC_SCHEMA);
    expect(changedTemplate(IPSEC_SCHEMA, values, { ...values, gateway: 'x' })).toBeUndefined();
  });
});

describe('applyTemplate', () => {
  const defaults = initialValues(IPSEC_SCHEMA);

  it.each([
    {
      name: 'fills untouched fields',
      before: defaults,
      template: 'fritzboxUser',
      expected: { ikeVersion: 'ikev1', mode: 'virtualIp', authMethod: 'psk' },
      kept: [],
    },
    {
      name: 'keeps a field the user changed',
      before: { ...defaults, ikeProposals: ['aes128-sha256-modp2048'] },
      template: 'lancom',
      expected: { ikeProposals: ['aes128-sha256-modp2048'], ikeVersion: 'ikev2' },
      kept: ['ikeProposals'],
    },
    {
      name: 'replaces values the previous template set',
      before: {
        ...defaults,
        template: 'lancom',
        ikeProposals: ['aes256gcm16-prfsha256-ecp256-modp2048', 'aes256-sha256-modp2048'],
        espProposals: ['aes256gcm16-ecp256-modp2048', 'aes256-sha256-modp2048'],
      },
      template: 'fritzbox',
      expected: { ikeProposals: ['aes256-sha512-sha256-modp2048'] },
      kept: [],
    },
    {
      name: 'fills an emptied list',
      before: { ...defaults, espProposals: [''] },
      template: 'fritzbox',
      expected: { espProposals: ['aes256-sha512-sha256-modp2048'] },
      kept: [],
    },
    {
      name: 'does not list a changed field that already holds the preset',
      before: { ...defaults, ikeVersion: 'ikev1' },
      template: 'fritzboxUser',
      expected: { ikeVersion: 'ikev1' },
      kept: [],
    },
  ])('$name', ({ before, template, expected, kept }) => {
    const result = applyTemplate(IPSEC_SCHEMA, before, choose(before, template));
    expect(result.values).toMatchObject({ template, ...expected });
    expect(result.kept).toEqual(kept);
  });
});

describe('forceTemplate', () => {
  it('sets every preset over the user values', () => {
    const before = { ...initialValues(IPSEC_SCHEMA), ikeProposals: ['aes128-sha256-modp2048'] };
    const values = forceTemplate(IPSEC_SCHEMA, before, choose(before, 'fritzbox'));
    expect(values.ikeProposals).toEqual(['aes256-sha512-sha256-modp2048']);
    expect(values.template).toBe('fritzbox');
  });
});
