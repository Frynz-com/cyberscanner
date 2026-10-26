import type { Metadata } from "next";
import { Network } from "lucide-react";
import { VulnScanToggle } from "@/components/domains/vuln-toggle";
import { PageHeader } from "@/components/shared/page-header";
import { getEntitlements } from "@/lib/core/entitlements";
import { daysAgoIso, formatDate, relativeTime } from "@/lib/labels";
import { createClient } from "@/lib/supabase/server";
import { requireOrg } from "@/lib/server/auth";

export const metadata: Metadata = { title: "Assets" };

const KIND: Record<string, string> = { domain: "Domain", subdomain: "Subdomain", ip: "IP-Adresse" };

function sourceLabel(s: string) {
  if (s.startsWith("subfinder:")) return `Subfinder (${s.slice(10)})`;
  if (s.startsWith("ct:")) return "Zertifikats-Logs";
  if (s === "dns") return "DNS-Auflösung";
  if (s === "customer") return "Von Ihnen hinzugefügt";
  if (s === "demo") return "Demo";
  return s;
}

export default async function AssetsPage({ searchParams }: { searchParams: Promise<{ kind?: string }> }) {
  const ctx = await requireOrg();
  const { kind } = await searchParams;
  const supabase = await createClient();
  let q = supabase.from("assets").select("id, kind, value, sources, first_seen_at, last_seen_at, is_active, vuln_scan_approved, metadata").eq("org_id", ctx.org.id).order("kind").order("value").limit(1000);
  if (kind && KIND[kind]) q = q.eq("kind", kind);
  const [{ data: assets }, { count: total }, ent] = await Promise.all([q, supabase.from("assets").select("id", { count: "exact", head: true }).eq("org_id", ctx.org.id), getEntitlements(supabase, ctx.org.id)]);
  const recent = daysAgoIso(7);

  return (
    <div className="space-y-6">
      <PageHeader title="Assets" description={`Nachvollziehbarer Bestand Ihrer öffentlich sichtbaren Systeme (${total ?? 0} Einträge). Nur aktuell im DNS existierende Subdomains werden aufgenommen.`} />
      <div className="flex gap-1.5">
        {[undefined, "domain", "subdomain", "ip"].map((k) => (
          <a key={k ?? "all"} href={k ? `/app/assets?kind=${k}` : "/app/assets"} className={`rounded-full border px-3 py-1 text-xs ${kind === k ? "border-foreground/30 bg-accent" : "text-muted-foreground"}`}>{k ? KIND[k] : "Alle"}</a>
        ))}
      </div>
      {(assets ?? []).length === 0 ? (
        <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed py-16 text-center">
          <Network className="size-6 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">Noch keine Assets erfasst. Sie erscheinen nach der ersten Prüfung.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border bg-card">
          <table className="w-full text-sm">
            <thead className="border-b text-left text-xs text-muted-foreground">
              <tr>
                <th className="px-4 py-2.5 font-medium">Asset</th>
                <th className="px-4 py-2.5 font-medium">Typ</th>
                <th className="hidden px-4 py-2.5 font-medium md:table-cell">Quelle</th>
                <th className="px-4 py-2.5 font-medium">Erstmals gesehen</th>
                <th className="hidden px-4 py-2.5 font-medium sm:table-cell">Zuletzt gesehen</th>
                {ent.limits.vuln_scan && <th className="px-4 py-2.5 font-medium" title="Aktive, nicht-destruktive Prüfung (Nuclei)">Aktive Prüfung</th>}
              </tr>
            </thead>
            <tbody className="divide-y">
              {assets!.map((a) => (
                <tr key={a.id} className={a.is_active ? "" : "opacity-50"}>
                  <td className="px-4 py-2.5 font-mono text-[13px]">
                    {a.value}
                    {a.first_seen_at > recent && a.kind === "subdomain" && <span className="ml-2 rounded-full bg-brand-soft px-1.5 py-0.5 font-sans text-[10px] font-medium text-brand">NEU</span>}
                    {(a.metadata as { dangling?: boolean })?.dangling && <span className="ml-2 rounded-full bg-sev-high/10 px-1.5 py-0.5 font-sans text-[10px] font-medium text-sev-high">verwaist</span>}
                  </td>
                  <td className="px-4 py-2.5 text-muted-foreground">{KIND[a.kind]}</td>
                  <td className="hidden px-4 py-2.5 text-xs text-muted-foreground md:table-cell">{a.sources.slice(0, 3).map(sourceLabel).join(", ")}</td>
                  <td className="px-4 py-2.5 text-muted-foreground">{formatDate(a.first_seen_at)}</td>
                  <td className="hidden px-4 py-2.5 text-muted-foreground sm:table-cell">{relativeTime(a.last_seen_at)}</td>
                  {ent.limits.vuln_scan && <td className="px-4 py-2.5">{a.kind !== "ip" && <VulnScanToggle assetId={a.id} approved={a.vuln_scan_approved} disabled={ctx.rank < 100 || ctx.org.is_demo} />}</td>}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
