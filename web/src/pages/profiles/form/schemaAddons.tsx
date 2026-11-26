import type { ReactNode } from 'react';
import type { FormSchema, Profile, SchemaField } from '../../../api/profiles';
import { schemaFields, type FormValues, type SecretStates } from '../schema/schemaValues';
import { IkeV1Notice, NetToNetRouteNotice } from './IpsecNotices';
import { KeyPairPanel } from './KeyPairPanel';
import { TemplatePanel } from './TemplatePanel';
import { templateFields } from './templatePresets';

export type FieldAddons = Record<string, ReactNode>;

export interface TemplateAddonOptions {
  schema: FormSchema;
  values: FormValues;
  kept: readonly string[];
  onForce: (fieldKey: string) => void;
}

/** The hint and kept-values notice below each template select of the schema. */
export function templateAddons({
  schema,
  values,
  kept,
  onForce,
}: TemplateAddonOptions): FieldAddons {
  const addons: FieldAddons = {};
  for (const field of templateFields(schema)) {
    const value = values[field.key];
    addons[field.key] = (
      <TemplatePanel
        schema={schema}
        field={field}
        value={typeof value === 'string' ? value : ''}
        kept={kept}
        onForce={() => onForce(field.key)}
      />
    );
  }
  return addons;
}

/** What an addon named by a schema field may read and do. */
export interface SchemaAddonContext {
  protocol: string;
  values: FormValues;
  secrets: SecretStates;
  profile: Profile | undefined;
  /** Takes a generated value for the secret field `key` as if typed in. */
  onGeneratedSecret: (key: string, value: string) => void;
}

/** Renders an addon below `field`; undefined shows nothing for now. */
type AddonRenderer = (field: SchemaField, context: SchemaAddonContext) => ReactNode;

/** The key pair generator below a private-key secret. */
const keyPairAddon: AddonRenderer = (field, context) => (
  <KeyPairPanel
    protocol={context.protocol}
    state={context.secrets[field.key]}
    storedPublicKey={context.profile?.derived?.publicKey}
    onGenerated={(value) => context.onGeneratedSecret(field.key, value)}
  />
);

/** IKEv1 chosen: the danger notice while the saved profile does not already show it. */
const ikeV1WarningAddon: AddonRenderer = (field, { values, profile }) => {
  const savedDanger = profile?.advisories.some((advisory) => advisory.code === 'ikev1_aggressive');
  return values[field.key] === 'ikev1' && !savedDanger ? <IkeV1Notice /> : undefined;
};

/** Net-to-net mode: the static route the LAN router needs for the remote subnets. */
const netToNetRouteAddon: AddonRenderer = (field, { values }) => {
  if (values[field.key] !== 'netToNet') {
    return undefined;
  }
  const subnets = values.remoteSubnets;
  return <NetToNetRouteNotice remoteSubnets={Array.isArray(subnets) ? subnets : []} />;
};

/** The addons a schema field can name in `addon`, by id. */
const ADDONS: ReadonlyMap<string, AddonRenderer> = new Map([
  ['keyPair', keyPairAddon],
  ['ikeV1Warning', ikeV1WarningAddon],
  ['netToNetRoute', netToNetRouteAddon],
]);

/** The addons the schema's fields name, keyed by field; unknown ids show nothing. */
export function schemaAddons(schema: FormSchema, context: SchemaAddonContext): FieldAddons {
  const addons: FieldAddons = {};
  for (const field of schemaFields(schema)) {
    const render = field.addon ? ADDONS.get(field.addon) : undefined;
    const addon = render?.(field, context);
    if (addon !== undefined) {
      addons[field.key] = addon;
    }
  }
  return addons;
}
