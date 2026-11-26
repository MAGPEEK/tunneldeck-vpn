import { useTranslation } from 'react-i18next';
import { Notice } from '../../../components/Notice';
import { useFirewall } from '../../../queries/queries';

/** The remote subnets as entered, without empty lines. */
function shownSubnets(lines: readonly string[]): string {
  return lines
    .map((line) => line.trim())
    .filter(Boolean)
    .join(', ');
}

/**
 * Net-to-net mode: the LAN router must send traffic for the remote subnets
 * to this host (SPEC §19). Names this host's LAN address when the firewall
 * state knows it.
 */
export function NetToNetRouteNotice({ remoteSubnets }: { remoteSubnets: readonly string[] }) {
  const { t } = useTranslation();
  const firewall = useFirewall();
  const address = firewall.data?.hostAddresses.join(', ') ?? '';
  const subnets = shownSubnets(remoteSubnets) || t('profileForm.ipsec.remoteSubnetsUnset');
  return (
    <Notice tone="info" title={t('profileForm.ipsec.staticRouteTitle')}>
      <p>
        {address
          ? t('profileForm.ipsec.staticRoute', { subnets, address })
          : t('profileForm.ipsec.staticRouteNoAddress', { subnets })}
      </p>
    </Notice>
  );
}

/** IKEv1 chosen in the form: the danger advisory before the profile is saved (SPEC §19.1). */
export function IkeV1Notice() {
  const { t } = useTranslation();
  return (
    <Notice tone="danger" title={t('advisory.title.ikev1_aggressive')}>
      <p>{t('advisory.ikev1_aggressive')}</p>
    </Notice>
  );
}
