import Link from "next/link";
import { Logo } from "@/components/brand/logo";
import { Button } from "@/components/ui/button";

export default function MarketingLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-dvh flex-col">
      <header className="sticky top-0 z-40 border-b border-transparent bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/70">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-4 px-4 sm:px-6">
          <Link href="/" aria-label="Startseite"><Logo /></Link>
          <nav className="hidden items-center gap-7 text-sm text-muted-foreground md:flex">
            <Link href="/#leistungen" className="hover:text-foreground">Leistungen</Link>
            <Link href="/#ablauf" className="hover:text-foreground">So funktioniert’s</Link>
            <Link href="/#preise" className="hover:text-foreground">Preise</Link>
            <Link href="/#faq" className="hover:text-foreground">FAQ</Link>
          </nav>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" asChild className="hidden sm:inline-flex"><Link href="/demo">Demo ansehen</Link></Button>
            <Button variant="ghost" size="sm" asChild><Link href="/login">Anmelden</Link></Button>
            <Button size="sm" asChild><Link href="/#check">Kostenlos prüfen</Link></Button>
          </div>
        </div>
      </header>
      <main className="flex-1">{children}</main>
      <footer className="border-t bg-card">
        <div className="mx-auto grid max-w-6xl gap-8 px-4 py-12 sm:px-6 md:grid-cols-4">
          <div className="space-y-3 md:col-span-2">
            <Logo />
            <p className="max-w-sm text-sm text-muted-foreground">Externe Sicherheitsüberwachung für mittelständische Unternehmen. Verständlich, nachvollziehbar und ohne Installation.</p>
          </div>
          <div className="space-y-2 text-sm">
            <p className="font-medium">Produkt</p>
            <Link href="/#check" className="block text-muted-foreground hover:text-foreground">Kostenloser Check</Link>
            <Link href="/#preise" className="block text-muted-foreground hover:text-foreground">Preise</Link>
            <Link href="/demo" className="block text-muted-foreground hover:text-foreground">Demo</Link>
          </div>
          <div className="space-y-2 text-sm">
            <p className="font-medium">Rechtliches</p>
            <Link href="/impressum" className="block text-muted-foreground hover:text-foreground">Impressum</Link>
            <Link href="/datenschutz" className="block text-muted-foreground hover:text-foreground">Datenschutz</Link>
            <Link href="/agb" className="block text-muted-foreground hover:text-foreground">AGB</Link>
          </div>
        </div>
        <div className="border-t py-5 text-center text-xs text-muted-foreground">© {new Date().getFullYear()} CyberSafe24 GmbH · Datenquellen u. a. <a href="https://haveibeenpwned.com" className="underline">Have I Been Pwned</a> (CC BY 4.0)</div>
      </footer>
    </div>
  );
}
