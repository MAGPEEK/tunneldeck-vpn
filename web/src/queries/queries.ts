import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  connect,
  disconnect,
  getConnection,
  getLogs,
  reconnect,
  type ConnectionStatus,
} from '../api/connection';
import { getFirewall } from '../api/firewall';
import { getDrivers, getProfile, getProfiles } from '../api/profiles';
import { queryKeys } from '../api/queryKeys';
import { getRemoteAccess } from '../api/remoteAccess';
import { getSystem } from '../api/system';

export function useConnection() {
  return useQuery({ queryKey: queryKeys.connection, queryFn: getConnection });
}

export function useLogs() {
  return useQuery({ queryKey: queryKeys.logs, queryFn: () => getLogs(), staleTime: Infinity });
}

export function useProfiles() {
  return useQuery({ queryKey: queryKeys.profiles, queryFn: getProfiles });
}

export function useProfile(id: string | undefined) {
  return useQuery({
    queryKey: queryKeys.profile(id ?? ''),
    queryFn: () => getProfile(id ?? ''),
    enabled: id !== undefined,
  });
}

export function useDrivers() {
  return useQuery({ queryKey: queryKeys.drivers, queryFn: getDrivers, staleTime: Infinity });
}

export function useFirewall() {
  return useQuery({ queryKey: queryKeys.firewall, queryFn: getFirewall });
}

export function useSystem() {
  return useQuery({ queryKey: queryKeys.system, queryFn: getSystem });
}

export function useRemoteAccess() {
  return useQuery({ queryKey: queryKeys.remoteAccess, queryFn: getRemoteAccess });
}

/** Connect, disconnect and reconnect; each answer replaces the cached status. */
export function useConnectionControl() {
  const client = useQueryClient();
  const onSuccess = (status: ConnectionStatus) => client.setQueryData(queryKeys.connection, status);
  return {
    connect: useMutation({ mutationFn: connect, onSuccess }),
    disconnect: useMutation({ mutationFn: disconnect, onSuccess }),
    reconnect: useMutation({ mutationFn: reconnect, onSuccess }),
  };
}

/** States in which a profile counts as in use (it cannot be deleted). */
export function isTunnelActive(status: ConnectionStatus | undefined, profileId: string): boolean {
  return status !== undefined && status.profileId === profileId && status.state !== 'disconnected';
}
