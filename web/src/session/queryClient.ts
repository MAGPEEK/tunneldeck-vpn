import { MutationCache, QueryCache, QueryClient } from '@tanstack/react-query';
import { isApiError } from '../api/client';
import type { Session } from '../api/session';

export const SESSION_QUERY_KEY = ['session'] as const;

/** Drops the signed-in state and every cached query that belonged to it. */
export function endSession(client: QueryClient): void {
  client.setQueryData<Session>(SESSION_QUERY_KEY, (session) =>
    session ? { ...session, authenticated: false, username: '' } : session,
  );
  client.removeQueries({ predicate: (query) => query.queryKey[0] !== SESSION_QUERY_KEY[0] });
}

function handleUnauthorized(client: QueryClient, error: unknown): void {
  if (!isApiError(error) || error.status !== 401) {
    return;
  }
  if (client.getQueryData<Session>(SESSION_QUERY_KEY)?.authenticated) {
    endSession(client);
  }
}

export function createQueryClient(): QueryClient {
  const client: QueryClient = new QueryClient({
    queryCache: new QueryCache({ onError: (error) => handleUnauthorized(client, error) }),
    mutationCache: new MutationCache({ onError: (error) => handleUnauthorized(client, error) }),
    defaultOptions: { queries: { retry: false } },
  });
  return client;
}
