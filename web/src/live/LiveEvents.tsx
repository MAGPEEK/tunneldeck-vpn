import { useQueryClient, type QueryClient } from '@tanstack/react-query';
import { useEffect, type ReactNode } from 'react';
import type {
  ChannelEvent,
  ConnectionStatus,
  LogLine,
  StateEvent,
  TrafficEvent,
} from '../api/connection';
import { queryKeys } from '../api/queryKeys';
import { appendLogLines } from './logLines';

const EVENTS_URL = '/api/events';

const MIN_RETRY_MS = 1000;
const MAX_RETRY_MS = 30000;

/** Delay before reconnect attempt `attempt` (0-based): 1 s, 2 s, 4 s … 30 s. */
function retryDelay(attempt: number): number {
  return Math.min(MAX_RETRY_MS, MIN_RETRY_MS * 2 ** attempt);
}

function parse<T>(event: Event): T | undefined {
  if (!(event instanceof MessageEvent) || typeof event.data !== 'string') {
    return undefined;
  }
  try {
    return JSON.parse(event.data) as T;
  } catch {
    return undefined;
  }
}

function applyState(client: QueryClient, event: StateEvent): void {
  client.setQueryData<ConnectionStatus>(queryKeys.connection, (status) => {
    if (!status) {
      return status;
    }
    const lastError =
      event.state === 'error'
        ? { code: event.code ?? '', message: event.message ?? '', time: event.since }
        : status.lastError;
    return {
      ...status,
      state: event.state,
      message: event.message,
      vpnIp: event.vpnIp,
      remote: event.remote,
      since: event.since,
      lastError,
    };
  });
  // The full status also names the profile and its advisories.
  void client.invalidateQueries({ queryKey: queryKeys.connection });
}

function applyTraffic(client: QueryClient, event: TrafficEvent): void {
  client.setQueryData<ConnectionStatus>(queryKeys.connection, (status) =>
    status ? { ...status, ...event } : status,
  );
}

/** Merges what the tunnel negotiated; an empty field keeps the known value. */
function applyChannel(client: QueryClient, event: ChannelEvent): void {
  client.setQueryData<ConnectionStatus>(queryKeys.connection, (status) =>
    status
      ? {
          ...status,
          dataCipher: event.dataCipher || status.dataCipher,
          controlChannel: event.controlChannel || status.controlChannel,
        }
      : status,
  );
}

function applyLog(client: QueryClient, line: LogLine): void {
  client.setQueryData<LogLine[]>(queryKeys.logs, (lines) =>
    lines ? appendLogLines(lines, [line]) : lines,
  );
}

function listen(client: QueryClient, source: EventSource): void {
  source.addEventListener('state', (event) => {
    const data = parse<StateEvent>(event);
    if (data) applyState(client, data);
  });
  source.addEventListener('traffic', (event) => {
    const data = parse<TrafficEvent>(event);
    if (data) applyTraffic(client, data);
  });
  source.addEventListener('channel', (event) => {
    const data = parse<ChannelEvent>(event);
    if (data) applyChannel(client, data);
  });
  source.addEventListener('log', (event) => {
    const data = parse<LogLine>(event);
    if (data) applyLog(client, data);
  });
}

/**
 * Keeps one EventSource on /api/events for the signed-in app and feeds its
 * events into the query cache. When the stream ends it reconnects with
 * backoff; refetching the status on each failure re-syncs what was missed
 * and, on a 401, hands over to the session flow.
 */
export function LiveEvents({ children }: { children: ReactNode }) {
  const client = useQueryClient();

  useEffect(() => {
    if (typeof EventSource === 'undefined') {
      return undefined;
    }
    let source: EventSource | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;

    const open = () => {
      source = new EventSource(EVENTS_URL, { withCredentials: true });
      listen(client, source);
      source.addEventListener('open', () => {
        attempt = 0;
      });
      source.addEventListener('error', () => {
        source?.close();
        void client.invalidateQueries({ queryKey: queryKeys.connection });
        timer = setTimeout(open, retryDelay(attempt));
        attempt += 1;
      });
    };
    open();

    return () => {
      clearTimeout(timer);
      source?.close();
    };
  }, [client]);

  return children;
}
