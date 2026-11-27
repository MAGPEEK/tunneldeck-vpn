import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { getAudit, type AuditFilter } from '../api/audit';
import {
  connect,
  disconnect,
  getConnection,
  getLogs,
  reconnect,
  type ConnectionStatus,
} from '../api/connection';
import { getFirewall, getFirewallDevices } from '../api/firewall';
import { getDrivers, getProfile, getProfiles } from '../api/profiles';
import { getPublicIpLookup } from '../api/publicIpLookup';
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

export function useFirewallDevices() {
  return useQuery({ queryKey: queryKeys.firewallDevices, queryFn: getFirewallDevices });
}

export function useSystem() {
  return useQuery({ queryKey: queryKeys.system, queryFn: getSystem });
}

export function useRemoteAccess() {
  return useQuery({ queryKey: queryKeys.remoteAccess, queryFn: getRemoteAccess });
}

export function usePublicIpLookup() {
  return useQuery({ queryKey: queryKeys.publicIpLookup, queryFn: getPublicIpLookup });
}

/** Pages of the audit log, newest first; each next page continues below the last entry. */
export function useAudit(filter: AuditFilter) {
  return useInfiniteQuery({
    queryKey: queryKeys.audit(filter),
    queryFn: ({ pageParam }) => getAudit(filter, pageParam),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => (last.hasMore ? last.entries.at(-1)?.id : undefined),
  });
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
