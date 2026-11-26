import { useCallback, useSyncExternalStore } from 'react';

function hasMatchMedia(): boolean {
  return typeof window.matchMedia === 'function';
}

/** Whether the media query matches; false where matchMedia is unavailable. */
export function useMediaQuery(query: string): boolean {
  const subscribe = useCallback(
    (onChange: () => void) => {
      if (!hasMatchMedia()) {
        return () => undefined;
      }
      const list = window.matchMedia(query);
      list.addEventListener('change', onChange);
      return () => list.removeEventListener('change', onChange);
    },
    [query],
  );
  return useSyncExternalStore(subscribe, () => hasMatchMedia() && window.matchMedia(query).matches);
}
