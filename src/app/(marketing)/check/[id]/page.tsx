import type { Metadata } from "next";
import { CheckResult } from "@/components/marketing/check-result";

export const metadata: Metadata = { title: "Kostenloser Sicherheitscheck", robots: { index: false } };

export default async function CheckPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <div className="mx-auto max-w-4xl px-4 py-12 sm:px-6">
      <CheckResult id={id} />
    </div>
  );
}
