/**
 * Site-specific network settings for the dashboard.
 *
 * This is the only place the UI knows about your addresses. Edit it to match
 * the `network:` block in `backend/config.yaml`, then rebuild the frontend.
 *
 * Nothing here is secret — it only controls how addresses are labelled and
 * shortened in charts and tables.
 */
export interface NetworkConfig {
  /** Friendly name shown next to internal addresses, e.g. "LAN (192.168.1.5)". */
  name: string;
  /**
   * Address prefixes treated as internal for labelling, each ending in a dot.
   * Should mirror `network.lan_cidrs` on the backend.
   */
  lanPrefixes: string[];
  /**
   * Your own public/WAN addresses, if you want them labelled as "WAN" instead
   * of shown in full. Optional — leave empty if the address changes often.
   */
  wanIps: string[];
}

export const NETWORK_CONFIG: NetworkConfig = {
  name: 'LAN',
  lanPrefixes: ['192.168.1.'],
  wanIps: [],
};

/** RFC 1918 / loopback ranges — used when no LAN prefix matches. */
export function isPrivateIp(ip: string | undefined | null): boolean {
  if (!ip) return false;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.')) return true;
  const match = /^172\.(\d{1,3})\./.exec(ip);
  if (match) {
    const second = Number(match[1]);
    return second >= 16 && second <= 31;
  }
  return false;
}

/** True when the address is on a configured LAN prefix. */
export function isLanIp(ip: string | undefined | null): boolean {
  if (!ip) return false;
  return NETWORK_CONFIG.lanPrefixes.some(prefix => ip.startsWith(prefix));
}

/** True when the address is one of our own public addresses. */
export function isWanIp(ip: string | undefined | null): boolean {
  if (!ip) return false;
  return NETWORK_CONFIG.wanIps.includes(ip);
}

/** True for anything that is ours: LAN, WAN, or another private range. */
export function isOwnIp(ip: string | undefined | null): boolean {
  return isLanIp(ip) || isWanIp(ip) || isPrivateIp(ip);
}

/** Full label for detail views, e.g. `LAN (192.168.1.5)` or `LAN (WAN)`. */
export function formatIpLabel(ip: string | undefined | null): string {
  if (!ip) return 'N/A';
  if (isWanIp(ip)) return `${NETWORK_CONFIG.name} (WAN)`;
  if (isLanIp(ip)) return `${NETWORK_CONFIG.name} (${ip})`;
  return ip;
}

/** Compact label for charts and dense tables, e.g. `.5` or `WAN`. */
export function formatIpShort(ip: string | undefined | null): string {
  if (!ip) return 'N/A';
  if (isWanIp(ip)) return 'WAN';
  for (const prefix of NETWORK_CONFIG.lanPrefixes) {
    if (ip.startsWith(prefix)) return '.' + ip.slice(prefix.length);
  }
  return ip;
}
