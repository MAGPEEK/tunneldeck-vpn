import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import styles from './FirewallPage.module.css';
import { INTENTS, type Intent } from './intents';

export interface IntentCardsProps {
  onChoose: (intent: Intent) => void;
}

/** "Add rule = intent first": one card per thing the user wants to do (SPEC §16.4). */
export function IntentCards({ onChoose }: IntentCardsProps) {
  const { t } = useTranslation();
  const titleId = useId();
  return (
    <section className={styles.intents} aria-labelledby={titleId}>
      <h3 id={titleId} className={styles.editorTitle}>
        {t('firewall.intent.title')}
      </h3>
      <ul className={styles.intentGrid}>
        {INTENTS.map((intent) => (
          <li key={intent}>
            <button
              type="button"
              className={styles.intentCard}
              aria-labelledby={`${titleId}-${intent}-title`}
              aria-describedby={`${titleId}-${intent}`}
              onClick={() => onChoose(intent)}
            >
              <span id={`${titleId}-${intent}-title`} className={styles.intentTitle}>
                {t(`firewall.intent.${intent}.title`)}
              </span>
              <span id={`${titleId}-${intent}`} className={styles.intentText}>
                {t(`firewall.intent.${intent}.text`)}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
