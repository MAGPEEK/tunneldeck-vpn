import { useTranslation } from 'react-i18next';
import type { ImportSeverity, ImportWarning } from '../../../api/profiles';
import { Notice, type NoticeTone } from '../../../components/Notice';
import { translateDynamic } from '../../../i18n/dynamic';
import styles from './ProfileForm.module.css';

const GROUPS: { severity: ImportSeverity; tone: NoticeTone }[] = [
  { severity: 'rejected', tone: 'danger' },
  { severity: 'warning', tone: 'warning' },
  { severity: 'info', tone: 'info' },
];

/** Import findings grouped by severity; rejected directives are marked as not imported. */
export function ImportWarnings({ warnings }: { warnings: ImportWarning[] }) {
  const { t } = useTranslation();
  return (
    <>
      {GROUPS.map(({ severity, tone }) => {
        const group = warnings.filter((warning) => warning.severity === severity);
        if (group.length === 0) {
          return null;
        }
        return (
          <Notice
            key={severity}
            tone={tone}
            title={t(`importWarnings.group.${severity}`, { count: group.length })}
          >
            <ul className={styles.warningList}>
              {group.map((warning, index) => (
                <li key={`${warning.line ?? 0}-${warning.code}-${index}`}>
                  {warning.line !== undefined && (
                    <span className={styles.warningLine}>
                      {t('importWarnings.line', { line: warning.line })}{' '}
                    </span>
                  )}
                  {warning.directive && (
                    <code className={styles.directive}>{warning.directive}</code>
                  )}{' '}
                  {severity === 'rejected' && <strong>{t('importWarnings.notImported')}: </strong>}
                  {translateDynamic(t, `importWarnings.code.${warning.code}`, warning.message)}
                </li>
              ))}
            </ul>
          </Notice>
        );
      })}
    </>
  );
}
