import type { ReactNode } from 'react';
import type { FormSchema, Profile } from '../../../api/profiles';
import type { FormValues } from '../schema/schemaValues';
import { IkeV1Notice, NetToNetRouteNotice } from './IpsecNotices';
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

/**
 * IPsec notices below their fields: the IKEv1 danger while the saved
 * profile does not already show it, and the static route hint in
 * net-to-net mode.
 */
export function ipsecAddons(
  protocol: string,
  values: FormValues,
  profile: Profile | undefined,
): FieldAddons {
  if (protocol !== 'ipsec') {
    return {};
  }
  const addons: FieldAddons = {};
  const savedDanger = profile?.advisories.some((advisory) => advisory.code === 'ikev1_aggressive');
  if (values.ikeVersion === 'ikev1' && !savedDanger) {
    addons.ikeVersion = <IkeV1Notice />;
  }
  if (values.mode === 'netToNet') {
    const subnets = values.remoteSubnets;
    addons.mode = <NetToNetRouteNotice remoteSubnets={Array.isArray(subnets) ? subnets : []} />;
  }
  return addons;
}
