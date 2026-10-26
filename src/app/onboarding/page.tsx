import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Logo } from "@/components/brand/logo";
import { createClient } from "@/lib/supabase/server";
import { getOrgContext, requireUser } from "@/lib/server/auth";
import { logoutAction } from "@/app/actions/auth";
import { OnboardingSteps } from "./steps";
import { CompanyStep, DomainStep, VerifyStep, AuthorizeStep, FirstScanStep } from "./step-forms";

export const metadata: Metadata = { title: "Einrichtung" };

const STEPS = ["Konto", "Unternehmen", "Domain", "Verifizieren", "Freigabe", "Erste Prüfung", "Ergebnisse"];

export default async function OnboardingPage() {
  const user = await requireUser();
  const ctx = await getOrgContext();
  const realOrg = ctx && !ctx.org.is_demo ? ctx : null;
  let step = 2;
  let content: React.ReactNode = <CompanyStep defaultEmail={user.email ?? ""} />;

  if (realOrg) {
    const supabase = await createClient();
    const { data: domains } = await supabase.from("domains").select("id, hostname, verification_status").eq("org_id", realOrg.org.id).order("created_at");
    const domain = domains?.[0];
    if (!domain) {
      step = 3;
      content = <DomainStep orgId={realOrg.org.id} />;
    } else if (domain.verification_status !== "verified") {
      step = 4;
      const { data: ch } = await supabase.from("verification_challenges").select("record_name, token, expires_at").eq("domain_id", domain.id).is("consumed_at", null).order("created_at", { ascending: false }).limit(1).maybeSingle();
      content = <VerifyStep domainId={domain.id} hostname={domain.hostname} recordName={ch?.record_name ?? ""} token={ch?.token ?? ""} />;
    } else {
      const { data: auth } = await supabase.from("scan_authorizations").select("id").eq("domain_id", domain.id).is("revoked_at", null).limit(1).maybeSingle();
      if (!auth) {
        step = 5;
        const { data: profile } = await supabase.from("profiles").select("full_name").eq("id", user.id).single();
        content = <AuthorizeStep domainId={domain.id} hostname={domain.hostname} orgName={realOrg.org.name} defaultName={profile?.full_name ?? ""} />;
      } else {
        const { data: job } = await supabase.from("scan_jobs").select("id, status").eq("domain_id", domain.id).eq("kind", "domain_scan").order("created_at", { ascending: false }).limit(1).maybeSingle();
        if (job?.status === "succeeded") redirect("/app");
        step = 6;
        content = <FirstScanStep domainId={domain.id} hostname={domain.hostname} existingJobId={job && ["queued", "running"].includes(job.status) ? job.id : null} />;
      }
    }
  }

  return (
    <div className="min-h-dvh bg-background">
      <header className="flex items-center justify-between border-b px-4 py-4 sm:px-8">
        <Link href="/"><Logo /></Link>
        <div className="flex items-center gap-4 text-sm">
          {realOrg && <Link href="/app" className="text-muted-foreground hover:text-foreground">Später fortfahren</Link>}
          <form action={logoutAction}><button className="text-muted-foreground hover:text-foreground">Abmelden</button></form>
        </div>
      </header>
      <main className="mx-auto max-w-2xl px-4 py-10 sm:py-14">
        <OnboardingSteps steps={STEPS} current={step} />
        <div className="mt-10">{content}</div>
      </main>
    </div>
  );
}
