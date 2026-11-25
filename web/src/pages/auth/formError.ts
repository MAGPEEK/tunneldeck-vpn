import type { TFunction } from 'i18next';
import { isApiError } from '../../api/client';

/** Message for errors that are not tied to a single field. */
export function genericErrorMessage(t: TFunction, error: unknown): string {
  return isApiError(error) && error.code === 'network'
    ? t('errors.network')
    : t('errors.unexpected');
}
