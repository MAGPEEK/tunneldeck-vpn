/** TanStack Query keys shared by pages and the live event stream. */
export const queryKeys = {
  connection: ['connection'] as const,
  logs: ['logs'] as const,
  profiles: ['profiles'] as const,
  profile: (id: string) => ['profiles', id] as const,
  drivers: ['drivers'] as const,
  firewall: ['firewall'] as const,
  firewallDevices: ['firewall', 'devices'] as const,
  system: ['system'] as const,
  remoteAccess: ['remote-access'] as const,
  publicIpLookup: ['public-ip-lookup'] as const,
  importDraft: ['import-draft'] as const,
};
