const CIDR_PATTERN = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;

/** The network octets and prefix length of an IPv4 CIDR, or `undefined` when it is none. */
function parseCidr(subnet: string): { octets: number[]; prefix: number } | undefined {
  const match = CIDR_PATTERN.exec(subnet.trim());
  if (!match) {
    return undefined;
  }
  const octets = match.slice(1, 5).map(Number);
  const prefix = Number(match[5]);
  if (octets.some((octet) => octet > 255) || prefix > 32) {
    return undefined;
  }
  return { octets, prefix };
}

/** The first usable address of a network smaller than a /24. */
function firstHost(octets: number[], prefix: number): string {
  const hostBits = 32 - prefix;
  const mask = hostBits >= 8 ? 0 : (0xff << hostBits) & 0xff;
  const network = (octets[3] ?? 0) & mask;
  const host = hostBits <= 1 ? network : network + 1;
  return [...octets.slice(0, 3), host].join('.');
}

/**
 * An example address in the detected LAN `subnet` for placeholders, e.g.
 * `192.168.2.0/24` with host part "x" gives "192.168.2.x" and
 * `10.1.0.0/16` gives "10.1.x.x". Octets the prefix (rounded up to a whole
 * octet) fixes keep the network's value; the free ones read "x" and the last
 * one is `hostPart`. A network smaller than a /24 has no free octet, so its
 * first usable address is the example. `undefined` when `subnet` is missing
 * or not an IPv4 CIDR, so callers fall back to a neutral text.
 */
export function lanExample(subnet: string | undefined, hostPart = 'x'): string | undefined {
  const parsed = subnet === undefined ? undefined : parseCidr(subnet);
  if (parsed === undefined) {
    return undefined;
  }
  const { octets, prefix } = parsed;
  if (prefix > 24) {
    return firstHost(octets, prefix);
  }
  const fixed = Math.max(1, Math.ceil(prefix / 8));
  const free = Array.from({ length: 4 - fixed }, (_, index) =>
    index === 3 - fixed ? hostPart : 'x',
  );
  return [...octets.slice(0, fixed), ...free].join('.');
}

/** `lanExample` for the first of `subnets` that is an IPv4 CIDR. */
export function firstLanExample(subnets: readonly string[], hostPart = 'x'): string | undefined {
  for (const subnet of subnets) {
    const example = lanExample(subnet, hostPart);
    if (example !== undefined) {
      return example;
    }
  }
  return undefined;
}
