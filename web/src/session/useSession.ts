import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getSession, login, logout, logoutEverywhere, setup } from '../api/session';
import { SESSION_QUERY_KEY, endSession } from './queryClient';

export function useSession() {
  return useQuery({ queryKey: SESSION_QUERY_KEY, queryFn: getSession });
}

function useRefreshSession() {
  const client = useQueryClient();
  return () => client.invalidateQueries({ queryKey: SESSION_QUERY_KEY });
}

export function useSetup() {
  const refreshSession = useRefreshSession();
  return useMutation({ mutationFn: setup, onSuccess: refreshSession });
}

export function useLogin() {
  const refreshSession = useRefreshSession();
  return useMutation({ mutationFn: login, onSuccess: refreshSession });
}

export function useLogout() {
  const client = useQueryClient();
  return useMutation({ mutationFn: logout, onSuccess: () => endSession(client) });
}

export function useLogoutEverywhere() {
  const client = useQueryClient();
  return useMutation({ mutationFn: logoutEverywhere, onSuccess: () => endSession(client) });
}
