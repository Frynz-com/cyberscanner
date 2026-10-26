import Link from "next/link";
import { Logo } from "@/components/brand/logo";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="grid min-h-dvh lg:grid-cols-[1fr_480px]">
      <div className="flex flex-col px-4 py-8 sm:px-10">
        <Link href="/" className="w-fit">
          <Logo />
        </Link>
        <div className="flex flex-1 items-center justify-center py-10">
          <div className="w-full max-w-sm">{children}</div>
        </div>
        <p className="text-xs text-muted-foreground">© CyberSafe24 GmbH · <Link href="/datenschutz" className="hover:underline">Datenschutz</Link> · <Link href="/impressum" className="hover:underline">Impressum</Link></p>
      </div>
      <aside className="relative hidden overflow-hidden border-l bg-primary text-primary-foreground lg:flex lg:flex-col lg:justify-end lg:p-10">
        <div className="absolute inset-0 opacity-[0.07] [background-image:radial-gradient(circle_at_1px_1px,white_1px,transparent_0)] [background-size:22px_22px]" />
        <div className="relative space-y-6">
          <p className="text-2xl leading-snug font-medium tracking-tight">„Wir wissen jetzt jeden Monat, was von außen sichtbar ist – und was unser IT-Dienstleister bereits behoben hat.“</p>
          <ul className="space-y-2 text-sm text-primary-foreground/70">
            <li>✓ Keine Software-Installation</li>
            <li>✓ Prüfung nur nach Domain-Nachweis und schriftlicher Freigabe</li>
            <li>✓ Daten in der EU, DSGVO-orientiert</li>
          </ul>
        </div>
      </aside>
    </div>
  );
}
