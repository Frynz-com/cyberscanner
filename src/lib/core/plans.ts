export interface PlanLimits {
  max_domains: number;
  max_subdomains_checked: number;
  min_scan_interval_hours: number;
  manual_scans_per_day: number;
  breach_monitoring: boolean;
  partner_invites: number;
  reports: boolean;
  vuln_scan: boolean;
}

export const INACTIVE_LIMITS: PlanLimits = {
  max_domains: 0,
  max_subdomains_checked: 0,
  min_scan_interval_hours: 744,
  manual_scans_per_day: 0,
  breach_monitoring: false,
  partner_invites: 0,
  reports: true,
  vuln_scan: false,
};

/** Abo-Status, die Leistungen freischalten (serverseitig ausgewertet). */
export function subscriptionIsActive(sub: { status: string; trial_ends_at: string | null } | null, now = new Date()): boolean {
  if (!sub) return false;
  if (sub.status === "active") return true;
  if (sub.status === "past_due") return true; // Kulanz während Stripe-Mahnlauf
  if (sub.status === "trialing") return !sub.trial_ends_at || new Date(sub.trial_ends_at) > now;
  return false;
}
