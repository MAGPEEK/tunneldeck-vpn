import { useEffect, useState } from 'react';

const TICK_MS = 1000;

export interface Countdown {
  /** Whole seconds left, 0 once the countdown has run out or never started. */
  remaining: number;
  /** The seconds the countdown started with; 0 before the first start. */
  started: number;
  start: (seconds: number) => void;
}

/** Counts whole seconds down from start(seconds), ticking once per second. */
export function useCountdown(): Countdown {
  const [until, setUntil] = useState<number>();
  const [started, setStarted] = useState(0);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (until === undefined) {
      return undefined;
    }
    const timer = setInterval(() => {
      const current = Date.now();
      setNow(current);
      if (current >= until) {
        clearInterval(timer);
      }
    }, TICK_MS);
    return () => clearInterval(timer);
  }, [until]);

  const start = (seconds: number) => {
    const current = Date.now();
    setNow(current);
    setStarted(seconds);
    setUntil(current + seconds * TICK_MS);
  };
  const remaining = until === undefined ? 0 : Math.max(0, Math.ceil((until - now) / TICK_MS));
  return { remaining, started, start };
}
