import { ArrowDown, Copy } from 'lucide-react';
import { useLayoutEffect, useRef, useState, type UIEvent } from 'react';
import { useTranslation } from 'react-i18next';
import type { LogLine } from '../../api/connection';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import {
  LEVEL_FILTERS,
  filterLogLines,
  formatLogLine,
  logClock,
  type LevelFilter,
} from '../../live/logLines';
import styles from './LogCard.module.css';

/** Distance from the bottom (px) that still counts as "at the latest line". */
const BOTTOM_SLACK = 8;

export function LogCard({ lines }: { lines: LogLine[] | undefined }) {
  const { t } = useTranslation();
  const [level, setLevel] = useState<LevelFilter>('all');
  const [text, setText] = useState('');
  const [following, setFollowing] = useState(true);
  const [copied, setCopied] = useState(false);
  const bodyRef = useRef<HTMLDivElement>(null);
  const visible = filterLogLines(lines ?? [], level, text);

  useLayoutEffect(() => {
    const body = bodyRef.current;
    if (following && body) {
      body.scrollTop = body.scrollHeight;
    }
  }, [visible.length, following, lines]);

  const onScroll = (event: UIEvent<HTMLDivElement>) => {
    const body = event.currentTarget;
    setFollowing(body.scrollHeight - body.scrollTop - body.clientHeight <= BOTTOM_SLACK);
  };

  const jumpToLatest = () => {
    const body = bodyRef.current;
    if (body) {
      body.scrollTop = body.scrollHeight;
    }
    setFollowing(true);
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(visible.map(formatLogLine).join('\n'));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  const actions = (
    <>
      <select
        className={styles.control}
        aria-label={t('log.level')}
        value={level}
        onChange={(event) => setLevel(event.currentTarget.value as LevelFilter)}
      >
        {LEVEL_FILTERS.map((filter) => (
          <option key={filter} value={filter}>
            {t(`log.filter.${filter}`)}
          </option>
        ))}
      </select>
      <input
        type="search"
        className={styles.control}
        aria-label={t('log.textFilter')}
        placeholder={t('log.textFilterPlaceholder')}
        value={text}
        onChange={(event) => setText(event.currentTarget.value)}
      />
      <Button
        icon={<Copy size={14} aria-hidden="true" />}
        disabled={visible.length === 0}
        onClick={() => void copy()}
      >
        {copied ? t('log.copied') : t('log.copy')}
      </Button>
    </>
  );

  return (
    <Card title={t('log.title')} actions={actions}>
      <div className={styles.frame}>
        <div
          ref={bodyRef}
          className={styles.body}
          role="log"
          aria-live="off"
          aria-label={t('log.title')}
          tabIndex={0}
          onScroll={onScroll}
        >
          {visible.length === 0 ? (
            <p className={styles.empty}>
              {lines === undefined ? t('log.loading') : t('log.empty')}
            </p>
          ) : (
            visible.map((line, index) => (
              <div
                key={index}
                className={`${styles.line} ${styles[line.level]}`}
                data-level={line.level}
              >
                <span className={styles.time}>{logClock(line)}</span>
                <span className={styles.text}>{line.text}</span>
              </div>
            ))
          )}
        </div>
        {!following && (
          <Button
            className={styles.jump}
            icon={<ArrowDown size={14} aria-hidden="true" />}
            onClick={jumpToLatest}
          >
            {t('log.jumpToLatest')}
          </Button>
        )}
      </div>
    </Card>
  );
}
