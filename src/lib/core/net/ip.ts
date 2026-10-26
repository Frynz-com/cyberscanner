import { BlockList, isIP } from "node:net";

/**
 * Nicht-öffentliche, reservierte und Metadaten-Adressbereiche.
 * Jede ausgehende Verbindung eines Scanners muss eine Zieladresse außerhalb dieser Bereiche haben.
 */
const blocked = new BlockList();
const V4: Array<[string, number]> = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.31.196.0", 24], ["192.52.193.0", 24], ["192.88.99.0", 24],
  ["192.168.0.0", 16], ["192.175.48.0", 24], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
  ["224.0.0.0", 4], ["240.0.0.0", 4],
];
const V6: Array<[string, number]> = [
  ["::", 128], ["::1", 128], ["100::", 64], ["2001::", 23], ["2001:db8::", 32], ["fc00::", 7], ["fe80::", 10],
  ["fec0::", 10], ["ff00::", 8],
];
for (const [net, prefix] of V4) blocked.addSubnet(net, prefix, "ipv4");
for (const [net, prefix] of V6) blocked.addSubnet(net, prefix, "ipv6");

/** Extrahiert eine eingebettete IPv4-Adresse (IPv4-mapped, NAT64, 6to4). */
function embeddedV4(ip: string): string | null {
  const lower = ip.toLowerCase();
  const mapped = lower.match(/^(?:::ffff:|::ffff:0:|64:ff9b::)(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return mapped[1];
  const hexMapped = lower.match(/^(?:::ffff:|64:ff9b::)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hexMapped) {
    const hi = parseInt(hexMapped[1], 16);
    const lo = parseInt(hexMapped[2], 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  const sixToFour = lower.match(/^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4}):/);
  if (sixToFour) {
    const hi = parseInt(sixToFour[1], 16);
    const lo = parseInt(sixToFour[2], 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return null;
}

export function isPublicIp(ip: string): boolean {
  const family = isIP(ip);
  if (family === 0) return false;
  if (family === 4) return !blocked.check(ip, "ipv4");
  const lower = ip.toLowerCase();
  if (lower.startsWith("::ffff:") || lower.startsWith("64:ff9b:") || lower.startsWith("2002:")) {
    const v4 = embeddedV4(lower);
    if (!v4) return false;
    return !blocked.check(v4, "ipv4");
  }
  return !blocked.check(ip, "ipv6");
}
