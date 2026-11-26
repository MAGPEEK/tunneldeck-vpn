import { FileUp } from 'lucide-react';
import { useRef, useState, type DragEvent, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import styles from './ProfileDropZone.module.css';

function carriesFiles(event: DragEvent): boolean {
  return Array.from(event.dataTransfer?.types ?? []).includes('Files');
}

export interface ProfileDropZoneProps {
  onFile: (file: File) => void;
  children: ReactNode;
}

/** Accepts a profile file dropped anywhere on its children and shows an overlay while dragging. */
export function ProfileDropZone({ onFile, children }: ProfileDropZoneProps) {
  const { t } = useTranslation();
  const [dragging, setDragging] = useState(false);
  // dragenter and dragleave fire for every child element crossed.
  const depth = useRef(0);

  const enter = (event: DragEvent) => {
    if (!carriesFiles(event)) return;
    event.preventDefault();
    depth.current += 1;
    setDragging(true);
  };
  const over = (event: DragEvent) => {
    if (!carriesFiles(event)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
  };
  const leave = (event: DragEvent) => {
    if (!carriesFiles(event)) return;
    depth.current = Math.max(0, depth.current - 1);
    if (depth.current === 0) setDragging(false);
  };
  const drop = (event: DragEvent) => {
    if (!carriesFiles(event)) return;
    event.preventDefault();
    depth.current = 0;
    setDragging(false);
    const file = event.dataTransfer.files[0];
    if (file) onFile(file);
  };

  return (
    <div
      className={styles.zone}
      data-testid="profile-drop-zone"
      onDragEnter={enter}
      onDragOver={over}
      onDragLeave={leave}
      onDrop={drop}
    >
      {children}
      {dragging && (
        <div className={styles.overlay} role="status">
          <FileUp size={32} aria-hidden="true" />
          <p className={styles.hint}>{t('profiles.dropHint')}</p>
        </div>
      )}
    </div>
  );
}
