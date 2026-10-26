import type { DocLink, Evaluation, Observation, RuleDefinition, Severity } from "./types";

/**
 * Regelkatalog der CyberSafe24 Risk Engine.
 * Jeder Schweregrad wird deterministisch aus technischen Fakten abgeleitet und begründet.
 * Keine KI, keine Zufallswerte.
 */

const f = (o: Observation, k: string) => o.facts[k];
const num = (o: Observation, k: string) => Number(o.facts[k] ?? 0);
const str = (o: Observation, k: string) => String(o.facts[k] ?? "");
const fixed = (severity: Severity, reason: string) => (): Evaluation => ({ severity, reasons: [reason] });

const DOCS = {
  spf: { label: "RFC 7208 – Sender Policy Framework", url: "https://www.rfc-editor.org/rfc/rfc7208" },
  dmarc: { label: "RFC 7489 – DMARC", url: "https://www.rfc-editor.org/rfc/rfc7489" },
  dkim: { label: "RFC 6376 – DKIM", url: "https://www.rfc-editor.org/rfc/rfc6376" },
  caa: { label: "RFC 8659 – CAA", url: "https://www.rfc-editor.org/rfc/rfc8659" },
  dnssec: { label: "RFC 9364 – DNSSEC", url: "https://www.rfc-editor.org/rfc/rfc9364" },
  securityTxt: { label: "RFC 9116 – security.txt", url: "https://www.rfc-editor.org/rfc/rfc9116" },
  mozillaTls: { label: "Mozilla SSL Configuration Generator", url: "https://ssl-config.mozilla.org/" },
  owaspHeaders: { label: "OWASP HTTP Headers Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html" },
  hsts: { label: "MDN – Strict-Transport-Security", url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security" },
  csp: { label: "MDN – Content-Security-Policy", url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP" },
  cookies: { label: "MDN – Set-Cookie", url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie" },
  kev: { label: "CISA Known Exploited Vulnerabilities", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
  hibp: { label: "Have I Been Pwned", url: "https://haveibeenpwned.com/" },
  takeover: { label: "OWASP – Subdomain Takeover", url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover" },
} satisfies Record<string, DocLink>;

const rules: RuleDefinition[] = [];
const rule = (r: RuleDefinition) => rules.push(r);

// ---------------------------------------------------------------------------
// E-Mail-Sicherheit (SPF, DMARC, DKIM)
// ---------------------------------------------------------------------------
rule({
  id: "email.spf.missing",
  check: "email.spf",
  category: "email",
  certainty: "confirmed",
  confidence: "high",
  title: () => "Kein SPF-Eintrag vorhanden",
  evaluate: (o) =>
    f(o, "hasMx")
      ? { severity: "medium", reasons: ["Domain empfängt E-Mails (MX vorhanden), legt aber nicht fest, welche Server in ihrem Namen senden dürfen"] }
      : { severity: "low", reasons: ["Kein MX-Eintrag: Domain wird vermutlich nicht für E-Mail genutzt, kann aber trotzdem für gefälschte Absender missbraucht werden"] },
  summary: (o) => `Für ${o.asset} ist nicht festgelegt, welche Server E-Mails im Namen Ihres Unternehmens versenden dürfen.`,
  businessImpact: () =>
    "Betrüger können leichter E-Mails versenden, die scheinbar von Ihrem Unternehmen stammen (z. B. gefälschte Rechnungen). Außerdem landen Ihre echten E-Mails häufiger im Spam.",
  recommendation: (o) =>
    f(o, "hasMx")
      ? "Lassen Sie Ihren IT-Dienstleister einen SPF-Eintrag anlegen, der alle legitimen Versanddienste (z. B. Microsoft 365, Newsletter-Tool) enthält und mit „-all“ oder „~all“ endet."
      : "Wenn über diese Domain keine E-Mails versendet werden, sollte ein SPF-Eintrag „v=spf1 -all“ angelegt werden. Damit ist klar: Niemand darf in ihrem Namen senden.",
  technicalDetails: (o) => `Keine TXT-Ressource mit „v=spf1“ unter ${o.asset} gefunden (DNS-Abfrage per DoH).`,
  verificationSteps: (o) => `dig +short TXT ${o.asset} | grep "v=spf1"`,
  docs: [DOCS.spf],
});

rule({
  id: "email.spf.multiple",
  check: "email.spf",
  category: "email",
  certainty: "confirmed",
  confidence: "high",
  title: () => "Mehrere SPF-Einträge (ungültig)",
  evaluate: fixed("medium", "Mehrere SPF-Einträge führen laut RFC 7208 zu einem permanenten Fehler – SPF wirkt dann gar nicht"),
  summary: (o) => `Für ${o.asset} existieren ${num(o, "count")} SPF-Einträge. Das ist ungültig und hebt den Schutz auf.`,
  businessImpact: () => "Empfangende Mailserver werten Ihren SPF-Eintrag als fehlerhaft. Gefälschte E-Mails werden dadurch nicht erkannt, echte E-Mails eventuell abgelehnt.",
  recommendation: () => "Die Einträge zu einem einzigen SPF-Eintrag zusammenführen lassen.",
  technicalDetails: (o) => `Gefundene SPF-Records:\n${(o.evidence.records as string[] | undefined)?.join("\n") ?? ""}`,
  verificationSteps: (o) => `dig +short TXT ${o.asset} | grep "v=spf1"`,
  docs: [DOCS.spf],
});

rule({
  id: "email.spf.permissive_all",
  check: "email.spf",
  category: "email",
  certainty: "confirmed",
  confidence: "high",
  title: (o) => `SPF erlaubt jedem Server den Versand („${str(o, "qualifier")}all“)`,
  evaluate: (o) =>
    str(o, "qualifier") === "+"
      ? { severity: "high", reasons: ["„+all“ erlaubt ausdrücklich jedem Server weltweit, im Namen der Domain zu senden"] }
      : { severity: "medium", reasons: ["„?all“ (neutral) bietet keinen Schutz gegen gefälschte Absender"] },
  summary: (o) => `Der SPF-Eintrag von ${o.asset} schützt nicht wirksam vor gefälschten Absendern.`,
  businessImpact: () => "Angreifer können E-Mails mit Ihrer Absenderadresse versenden, ohne dass Empfänger dies anhand von SPF erkennen.",
  recommendation: () => "SPF-Eintrag mit „-all“ (oder übergangsweise „~all“) abschließen und alle legitimen Versender explizit aufnehmen.",
  technicalDetails: (o) => `SPF-Record: ${str(o, "record")}`,
  verificationSteps: (o) => `dig +short TXT ${o.asset} | grep "v=spf1"`,
  docs: [DOCS.spf],
});

rule({
  id: "email.spf.no_all",
  check: "email.spf",
  category: "email",
  certainty: "confirmed",
  confidence: "high",
  title: () => "SPF-Eintrag ohne abschließende Regel",
  evaluate: fixed("low", "Ohne „all“-Mechanismus ist das Ergebnis für nicht gelistete Server neutral"),
  summary: (o) => `Der SPF-Eintrag von ${o.asset} legt nicht fest, was mit unbekannten Servern passieren soll.`,
  businessImpact: () => "Der Schutz gegen gefälschte Absender ist eingeschränkt.",
  recommendation: () => "SPF-Eintrag mit „-all“ oder „~all“ abschließen.",
  technicalDetails: (o) => `SPF-Record: ${str(o, "record")}`,
  verificationSteps: (o) => `dig +short TXT ${o.asset} | grep "v=spf1"`,
  docs: [DOCS.spf],
});

rule({
  id: "email.spf.too_many_lookups",
  check: "email.spf",
  category: "email",
  certainty: "confirmed",
  confidence: "high",
  title: (o) => `SPF benötigt zu viele DNS-Abfragen (${num(o, "lookups")} von max. 10)`,
  evaluate: fixed("medium", "Mehr als 10 DNS-Lookups führen laut RFC 7208 zu einem permanenten Fehler"),
  summary: (o) => `Der SPF-Eintrag von ${o.asset} ist so verschachtelt, dass viele Mailserver ihn als fehlerhaft werten.`,
  businessImpact: () => "SPF wirkt nicht zuverlässig. Echte E-Mails können abgelehnt werden, gefälschte werden nicht erkannt.",
  recommendation: () => "Nicht mehr benötigte „include“-Einträge entfernen oder SPF-Einträge vereinfachen lassen.",
  technicalDetails: (o) => `Gezählte DNS-Lookup-Mechanismen (include, a, mx, ptr, exists, redirect): ${num(o, "lookups")}. Record: ${str(o, "record")}`,
  docs: [DOCS.spf],
});

rule({
  id: "email.dmarc.missing",
  check: "email.dmarc",
  category: "email",
  certainty: "confirmed",
  confidence: "high",
  title: () => "Kein DMARC-Eintrag vorhanden",
  evaluate: (o) =>
    f(o, "hasMx")
      ? { severity: "medium", reasons: ["Ohne DMARC gibt es keine Anweisung an Empfänger, wie mit gefälschten E-Mails Ihrer Domain umzugehen ist"] }
      : { severity: "low", reasons: ["Domain ohne MX: Missbrauch als Absender trotzdem möglich, aber geringere Relevanz"] },
  summary: (o) => `Für ${o.asset} ist keine DMARC-Richtlinie veröffentlicht.`,
  businessImpact: () =>
    "Gefälschte E-Mails mit Ihrer Absenderadresse (z. B. „CEO-Fraud“ oder falsche Rechnungen) werden von Empfängern nicht gezielt abgewiesen. Sie erhalten außerdem keine Berichte über Missbrauch.",
  recommendation: () =>
    "DMARC zunächst mit „p=none“ und Berichtsadresse (rua) einführen, Berichte auswerten und anschließend schrittweise auf „p=quarantine“ bzw. „p=reject“ verschärfen.",
  technicalDetails: (o) => `Keine TXT-Ressource mit „v=DMARC1“ unter _dmarc.${o.asset} gefunden.`,
  verificationSteps: (o) => `dig +short TXT _dmarc.${o.asset}`,
  docs: [DOCS.dmarc],
});

rule({
  id: "email.dmarc.policy_none",
  check: "email.dmarc",
  category: "email",
  certainty: "confirmed",
  confidence: "high",
  title: () => "DMARC nur im Beobachtungsmodus (p=none)",
  evaluate: fixed("low", "DMARC ist vorhanden, gefälschte E-Mails werden aber nicht abgewiesen"),
  summary: (o) => `DMARC ist für ${o.asset} eingerichtet, gefälschte E-Mails werden aber noch zugestellt.`,
  businessImpact: () => "Der Schutz vor gefälschten Absendern ist noch nicht aktiv. Der Beobachtungsmodus ist nur als Übergangsphase gedacht.",
  recommendation: () => "Nach Auswertung der DMARC-Berichte die Richtlinie auf „p=quarantine“ und später „p=reject“ anheben.",
  technicalDetails: (o) => `DMARC-Record: ${str(o, "record")}`,
  verificationSteps: (o) => `dig +short TXT _dmarc.${o.asset}`,
  docs: [DOCS.dmarc],
});

rule({
  id: "email.dmarc.multiple",
  check: "email.dmarc",
  category: "email",
  certainty: "confirmed",
  confidence: "high",
  title: () => "Mehrere DMARC-Einträge (ungültig)",
  evaluate: fixed("medium", "Bei mehreren DMARC-Records ignorieren Empfänger DMARC laut RFC 7489 vollständig"),
  summary: (o) => `Für _dmarc.${o.asset} existieren mehrere DMARC-Einträge. DMARC wird dadurch wirkungslos.`,
  businessImpact: () => "Ihr DMARC-Schutz greift nicht.",
  recommendation: () => "Auf genau einen DMARC-Eintrag reduzieren.",
  technicalDetails: (o) => `Records:\n${(o.evidence.records as string[] | undefined)?.join("\n") ?? ""}`,
  docs: [DOCS.dmarc],
});

rule({
  id: "email.dmarc.partial",
  check: "email.dmarc",
  category: "email",
  certainty: "confirmed",
  confidence: "high",
  title: (o) => `DMARC gilt nur für ${num(o, "pct")} % der E-Mails`,
  evaluate: fixed("low", "Ein pct-Wert unter 100 wendet die Richtlinie nur auf einen Teil der E-Mails an"),
  summary: (o) => `Die DMARC-Richtlinie von ${o.asset} wird nur teilweise angewendet.`,
  businessImpact: () => "Ein Teil gefälschter E-Mails wird weiterhin zugestellt.",
  recommendation: () => "Den Parameter pct auf 100 setzen oder entfernen.",
  technicalDetails: (o) => `DMARC-Record: ${str(o, "record")}`,
  docs: [DOCS.dmarc],
});

rule({
  id: "email.dmarc.no_reporting",
  check: "email.dmarc",
  category: "email",
  certainty: "informational",
  confidence: "high",
  title: () => "DMARC ohne Berichtsadresse",
  evaluate: fixed("info", "Ohne rua-Adresse erhalten Sie keine Auswertungen zu Missbrauchsversuchen"),
  summary: (o) => `Für ${o.asset} ist keine Adresse für DMARC-Berichte hinterlegt.`,
  businessImpact: () => "Sie erfahren nicht, ob jemand versucht, E-Mails in Ihrem Namen zu fälschen.",
  recommendation: () => "Eine Berichtsadresse (rua=mailto:…) ergänzen, idealerweise mit einem Auswertungsdienst.",
  technicalDetails: (o) => `DMARC-Record: ${str(o, "record")}`,
  docs: [DOCS.dmarc],
});

rule({
  id: "email.dkim.not_checkable",
  check: "email.dkim",
  category: "email",
  certainty: "not_checkable",
  confidence: "low",
  title: () => "DKIM konnte von außen nicht geprüft werden",
  evaluate: fixed("info", "DKIM-Schlüssel sind nur mit bekanntem Selektor abrufbar; gängige Selektoren wurden ohne Treffer geprüft"),
  summary: (o) => `Für ${o.asset} wurde unter gängigen Namen kein DKIM-Schlüssel gefunden. Das bedeutet nicht zwingend, dass DKIM fehlt.`,
  businessImpact: () => "DKIM signiert ausgehende E-Mails und ist Voraussetzung für einen wirksamen DMARC-Schutz.",
  recommendation: () => "IT-Dienstleister fragen, ob DKIM für alle Versanddienste aktiv ist. Den verwendeten Selektor können Sie uns mitteilen.",
  technicalDetails: (o) => `Geprüfte Selektoren: ${(o.evidence.selectorsTried as string[] | undefined)?.join(", ") ?? ""}`,
  docs: [DOCS.dkim],
});

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------
rule({
  id: "dns.dnssec.unsigned",
  check: "dns.dnssec",
  category: "dns",
  certainty: "confirmed",
  confidence: "high",
  title: () => "DNSSEC nicht aktiviert",
  evaluate: fixed("low", "Ohne DNSSEC können DNS-Antworten unterwegs nicht auf Echtheit geprüft werden; Angriffe sind aufwendig, aber möglich"),
  summary: (o) => `Die DNS-Einträge von ${o.asset} sind nicht kryptografisch signiert.`,
  businessImpact: () => "Besucher und Mailserver können gefälschte DNS-Antworten nicht erkennen. Das Risiko ist gering, DNSSEC gilt aber als Stand der Technik.",
  recommendation: () => "Beim Domain- bzw. DNS-Anbieter DNSSEC aktivieren (bei vielen Anbietern ein Klick).",
  technicalDetails: (o) => `Kein DS-Record in der Elternzone gefunden; Antworten für ${o.asset} ohne AD-Flag.`,
  verificationSteps: (o) => `dig +short DS ${o.asset}`,
  docs: [DOCS.dnssec],
});

rule({
  id: "dns.dnssec.broken",
  check: "dns.dnssec",
  category: "dns",
  certainty: "confirmed",
  confidence: "high",
  title: () => "DNSSEC fehlerhaft konfiguriert",
  evaluate: fixed("high", "Validierende Resolver liefern SERVFAIL – die Domain ist für viele Nutzer nicht erreichbar"),
  summary: (o) => `Die DNSSEC-Signatur von ${o.asset} ist ungültig.`,
  businessImpact: () => "Website und E-Mail können für Kunden und Partner mit validierenden Resolvern komplett ausfallen.",
  recommendation: () => "Sofort DNS-Anbieter kontaktieren: DS-Record und Schlüssel abgleichen oder DNSSEC kontrolliert deaktivieren.",
  technicalDetails: () => "Abfrage mit DNSSEC-Validierung: SERVFAIL; Abfrage mit CD-Flag (ohne Validierung): erfolgreich.",
  docs: [DOCS.dnssec],
});

rule({
  id: "dns.caa.missing",
  check: "dns.caa",
  category: "dns",
  certainty: "confirmed",
  confidence: "high",
  title: () => "Keine CAA-Richtlinie für Zertifikate",
  evaluate: fixed("low", "Ohne CAA darf jede Zertifizierungsstelle Zertifikate für die Domain ausstellen"),
  summary: (o) => `Für ${o.asset} ist nicht festgelegt, welche Zertifizierungsstellen Zertifikate ausstellen dürfen.`,
  businessImpact: () => "Fehlausstellungen von Zertifikaten werden nicht verhindert. Geringes, aber einfach zu behebendes Risiko.",
  recommendation: () => "CAA-Eintrag für die tatsächlich genutzte Zertifizierungsstelle anlegen (z. B. letsencrypt.org).",
  technicalDetails: (o) => `Keine CAA-Records für ${o.asset} gefunden.`,
  verificationSteps: (o) => `dig +short CAA ${o.asset}`,
  docs: [DOCS.caa],
});

rule({
  id: "dns.ns.single",
  check: "dns.ns",
  category: "dns",
  certainty: "confirmed",
  confidence: "high",
  title: () => "Nur ein Nameserver eingetragen",
  evaluate: fixed("low", "Ein einzelner Nameserver ist ein Single Point of Failure"),
  summary: (o) => `${o.asset} hängt von einem einzigen Nameserver ab.`,
  businessImpact: () => "Fällt dieser Server aus, sind Website und E-Mail nicht erreichbar.",
  recommendation: () => "Mindestens zwei Nameserver in unterschiedlichen Netzen eintragen.",
  technicalDetails: (o) => `NS: ${(o.evidence.ns as string[] | undefined)?.join(", ") ?? ""}`,
  docs: [],
});

rule({
  id: "dns.dangling_cname",
  check: "dns.dangling",
  category: "dns",
  certainty: "potential",
  confidence: "medium",
  title: (o) => `Verwaister DNS-Verweis auf ${str(o, "target")}`,
  evaluate: fixed("high", "Ein CNAME zeigt auf einen nicht existierenden Namen – je nach Dienst kann ein Dritter diesen Namen registrieren und Inhalte unter Ihrer Subdomain ausliefern"),
  summary: (o) => `${o.asset} verweist auf ${str(o, "target")}, das nicht mehr existiert.`,
  businessImpact: () =>
    "Wenn der Zieldienst frei registrierbar ist, könnten Angreifer unter Ihrer Subdomain Phishing-Seiten betreiben (Subdomain-Übernahme). Ob das hier möglich ist, hängt vom Dienst ab – deshalb „mögliches Risiko“.",
  recommendation: () => "Nicht mehr genutzte DNS-Einträge löschen oder den Zieldienst wieder einrichten.",
  technicalDetails: (o) => `${o.asset} CNAME ${str(o, "target")} → NXDOMAIN`,
  verificationSteps: (o) => `dig CNAME ${o.asset}\ndig A ${str(o, "target")}`,
  docs: [DOCS.takeover],
});

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------
rule({
  id: "tls.cert.expired",
  check: "tls.cert",
  category: "tls",
  certainty: "confirmed",
  confidence: "high",
  title: () => "TLS-Zertifikat abgelaufen",
  evaluate: fixed("critical", "Abgelaufenes Zertifikat: Browser zeigen eine Sicherheitswarnung, verschlüsselte Verbindungen schlagen fehl"),
  summary: (o) => `Das Zertifikat von ${o.asset} ist seit ${str(o, "validTo")} abgelaufen.`,
  businessImpact: () => "Besucher sehen eine Warnseite. Vertrauensverlust und Ausfall von Kontaktformularen, Shops oder Kundenportalen.",
  recommendation: () => "Zertifikat sofort erneuern und automatische Verlängerung (z. B. ACME/Let’s Encrypt) einrichten.",
  technicalDetails: (o) => `Subject: ${str(o, "subject")}\nAussteller: ${str(o, "issuer")}\nGültig bis: ${str(o, "validTo")}`,
  verificationSteps: (o) => `openssl s_client -connect ${o.asset}:443 -servername ${o.asset} </dev/null | openssl x509 -noout -dates`,
  docs: [DOCS.mozillaTls],
});

rule({
  id: "tls.cert.expiring",
  check: "tls.cert",
  category: "tls",
  certainty: "confirmed",
  confidence: "high",
  title: (o) => `TLS-Zertifikat läuft in ${num(o, "daysLeft")} Tagen ab`,
  evaluate: (o) => {
    const d = num(o, "daysLeft");
    if (d <= 7) return { severity: "high", reasons: [`Nur noch ${d} Tage gültig (Schwelle: ≤ 7 Tage)`] };
    if (d <= 14) return { severity: "medium", reasons: [`Nur noch ${d} Tage gültig (Schwelle: ≤ 14 Tage)`] };
    return { severity: "low", reasons: [`Noch ${d} Tage gültig (Schwelle: ≤ 30 Tage)`] };
  },
  summary: (o) => `Das Zertifikat von ${o.asset} läuft am ${str(o, "validTo")} ab.`,
  businessImpact: () => "Wird das Zertifikat nicht rechtzeitig erneuert, sehen Besucher eine Sicherheitswarnung.",
  recommendation: () => "Verlängerung prüfen; idealerweise automatisieren.",
  technicalDetails: (o) => `Subject: ${str(o, "subject")}\nAussteller: ${str(o, "issuer")}\nGültig bis: ${str(o, "validTo")}`,
  verificationSteps: (o) => `openssl s_client -connect ${o.asset}:443 -servername ${o.asset} </dev/null | openssl x509 -noout -enddate`,
  docs: [DOCS.mozillaTls],
});

rule({
  id: "tls.cert.hostname_mismatch",
  check: "tls.cert",
  category: "tls",
  certainty: "confirmed",
  confidence: "high",
  title: () => "Zertifikat passt nicht zum Hostnamen",
  evaluate: fixed("high", "Browser lehnen die Verbindung mit einer Warnung ab"),
  summary: (o) => `Das Zertifikat von ${o.asset} ist für einen anderen Namen ausgestellt.`,
  businessImpact: () => "Besucher sehen eine Sicherheitswarnung; Nutzer werden daran gewöhnt, Warnungen wegzuklicken.",
  recommendation: () => "Zertifikat mit korrektem Namen (SAN) ausstellen oder nicht genutzten Hostnamen entfernen.",
  technicalDetails: (o) => `Zertifikatsnamen: ${(o.evidence.altNames as string[] | undefined)?.join(", ") ?? str(o, "subject")}`,
  verificationSteps: (o) => `openssl s_client -connect ${o.asset}:443 -servername ${o.asset} </dev/null | openssl x509 -noout -ext subjectAltName`,
  docs: [DOCS.mozillaTls],
});

rule({
  id: "tls.cert.untrusted",
  check: "tls.cert",
  category: "tls",
  certainty: "confirmed",
  confidence: "high",
  title: () => "Zertifikat wird nicht vertraut",
  evaluate: (o) =>
    f(o, "selfSigned")
      ? { severity: "high", reasons: ["Selbstsigniertes Zertifikat – kein Browser vertraut ihm"] }
      : { severity: "high", reasons: [`Zertifikatskette ungültig (${str(o, "error")})`] },
  summary: (o) => `Die Zertifikatskette von ${o.asset} ist nicht vertrauenswürdig.`,
  businessImpact: () => "Besucher sehen eine Sicherheitswarnung; Verbindungen sind gegen Abhören nicht verlässlich geschützt.",
  recommendation: () => "Zertifikat einer vertrauenswürdigen Zertifizierungsstelle verwenden und vollständige Kette ausliefern.",
  technicalDetails: (o) => `Fehler: ${str(o, "error")}\nAussteller: ${str(o, "issuer")}`,
  docs: [DOCS.mozillaTls],
});

rule({
  id: "tls.protocol.legacy",
  check: "tls.protocol",
  category: "tls",
  certainty: "confirmed",
  confidence: "high",
  title: (o) => `Veraltete Verschlüsselung erlaubt (${str(o, "protocol")})`,
  evaluate: fixed("medium", "TLS 1.0/1.1 gelten seit RFC 8996 als veraltet und unsicher"),
  summary: (o) => `${o.asset} akzeptiert noch das veraltete Protokoll ${str(o, "protocol")}.`,
  businessImpact: () => "Veraltete Verschlüsselung kann unter Umständen gebrochen werden und widerspricht gängigen Compliance-Anforderungen.",
  recommendation: () => "TLS 1.0 und 1.1 auf dem Server deaktivieren; nur TLS 1.2 und 1.3 zulassen.",
  technicalDetails: (o) => `Erfolgreicher Handshake mit ${str(o, "protocol")}.`,
  verificationSteps: (o) => `openssl s_client -connect ${o.asset}:443 -servername ${o.asset} -tls1_1 </dev/null`,
  docs: [DOCS.mozillaTls],
});

rule({
  id: "tls.cert.weak_key",
  check: "tls.cert",
  category: "tls",
  certainty: "confirmed",
  confidence: "high",
  title: (o) => `Schwacher Zertifikatsschlüssel (${num(o, "bits")} Bit)`,
  evaluate: fixed("medium", "RSA-Schlüssel unter 2048 Bit gelten als unsicher"),
  summary: (o) => `Das Zertifikat von ${o.asset} verwendet einen zu kurzen Schlüssel.`,
  businessImpact: () => "Die Verschlüsselung entspricht nicht dem Stand der Technik.",
  recommendation: () => "Neues Zertifikat mit mindestens 2048-Bit-RSA- oder ECDSA-Schlüssel ausstellen.",
  technicalDetails: (o) => `Schlüssellänge: ${num(o, "bits")} Bit`,
  docs: [DOCS.mozillaTls],
});

// ---------------------------------------------------------------------------
// Web / HTTP
// ---------------------------------------------------------------------------
rule({
  id: "web.https.unavailable",
  check: "web.https",
  category: "web",
  certainty: "confirmed",
  confidence: "medium",
  title: () => "Website nicht per HTTPS erreichbar",
  evaluate: fixed("medium", "Der Host hat eine öffentliche IP-Adresse, beantwortet aber keine HTTPS-Verbindung"),
  summary: (o) => `${o.asset} konnte nicht verschlüsselt (HTTPS) aufgerufen werden.`,
  businessImpact: () => "Falls dort eine Website betrieben wird, werden Daten unverschlüsselt übertragen oder Besucher erhalten Fehlermeldungen.",
  recommendation: () => "HTTPS mit gültigem Zertifikat einrichten oder den DNS-Eintrag entfernen, falls der Host nicht mehr genutzt wird.",
  technicalDetails: (o) => `Fehler: ${str(o, "error")}`,
  docs: [DOCS.mozillaTls],
});

rule({
  id: "web.redirect.no_https",
  check: "web.redirect",
  category: "web",
  certainty: "confirmed",
  confidence: "high",
  title: () => "Keine automatische Weiterleitung auf HTTPS",
  evaluate: fixed("medium", "Die unverschlüsselte Version der Website wird ohne Weiterleitung ausgeliefert"),
  summary: (o) => `Wer http://${o.asset} aufruft, wird nicht auf die sichere Version umgeleitet.`,
  businessImpact: () => "Besucher können unbemerkt eine unverschlüsselte Verbindung nutzen, z. B. in öffentlichen WLANs.",
  recommendation: () => "Dauerhafte Weiterleitung (301/308) von HTTP auf HTTPS einrichten.",
  technicalDetails: (o) => `GET http://${o.asset}/ → Status ${num(o, "status")} ohne Weiterleitung auf https://`,
  verificationSteps: (o) => `curl -sI http://${o.asset}/`,
  docs: [DOCS.hsts],
});

rule({
  id: "web.headers.hsts_missing",
  check: "web.headers",
  category: "web",
  certainty: "confirmed",
  confidence: "high",
  title: () => "HSTS-Header fehlt",
  evaluate: fixed("medium", "Ohne HSTS können Browser auf unverschlüsselte Verbindungen herabgestuft werden"),
  summary: (o) => `${o.asset} weist Browser nicht an, ausschließlich verschlüsselt zu verbinden.`,
  businessImpact: () => "Angreifer im selben Netz (z. B. Hotel-WLAN) könnten Verbindungen abfangen oder umleiten.",
  recommendation: () => "Header „Strict-Transport-Security: max-age=31536000; includeSubDomains“ setzen (vorher prüfen, dass alle Subdomains HTTPS unterstützen).",
  technicalDetails: (o) => `Kein Strict-Transport-Security-Header in der Antwort von ${str(o, "url")}`,
  verificationSteps: (o) => `curl -sI https://${o.asset}/ | grep -i strict-transport`,
  docs: [DOCS.hsts, DOCS.owaspHeaders],
});

rule({
  id: "web.headers.hsts_short",
  check: "web.headers",
  category: "web",
  certainty: "confirmed",
  confidence: "high",
  title: () => "HSTS-Gültigkeit zu kurz",
  evaluate: fixed("low", "max-age unter 180 Tagen bietet nur eingeschränkten Schutz"),
  summary: (o) => `Der HSTS-Header von ${o.asset} gilt nur ${Math.round(num(o, "maxAge") / 86400)} Tage.`,
  businessImpact: () => "Der Schutz vor Herabstufung auf HTTP ist zeitlich begrenzt.",
  recommendation: () => "max-age auf mindestens 15552000 (180 Tage), besser 31536000 (1 Jahr) setzen.",
  technicalDetails: (o) => `Strict-Transport-Security: ${str(o, "header")}`,
  docs: [DOCS.hsts],
});

rule({
  id: "web.headers.csp_missing",
  check: "web.headers",
  category: "web",
  certainty: "confirmed",
  confidence: "high",
  title: () => "Content-Security-Policy fehlt",
  evaluate: fixed("low", "CSP ist eine zusätzliche Schutzschicht gegen Cross-Site-Scripting; ihr Fehlen ist keine Schwachstelle an sich"),
  summary: (o) => `${o.asset} nutzt keine Content-Security-Policy.`,
  businessImpact: () => "Falls die Website eine Schwachstelle für eingeschleusten Code hat, fehlt eine wichtige zweite Verteidigungslinie.",
  recommendation: () => "Eine Content-Security-Policy schrittweise einführen (zunächst im Report-Only-Modus).",
  technicalDetails: (o) => `Kein Content-Security-Policy-Header in der Antwort von ${str(o, "url")}`,
  docs: [DOCS.csp, DOCS.owaspHeaders],
});

rule({
  id: "web.headers.xcto_missing",
  check: "web.headers",
  category: "web",
  certainty: "confirmed",
  confidence: "high",
  title: () => "X-Content-Type-Options fehlt",
  evaluate: fixed("low", "Browser dürfen Dateitypen erraten (MIME-Sniffing)"),
  summary: (o) => `${o.asset} setzt den Header X-Content-Type-Options nicht.`,
  businessImpact: () => "Geringes Risiko; einfache Härtungsmaßnahme.",
  recommendation: () => "Header „X-Content-Type-Options: nosniff“ setzen.",
  technicalDetails: (o) => `Header fehlt in der Antwort von ${str(o, "url")}`,
  docs: [DOCS.owaspHeaders],
});

rule({
  id: "web.headers.clickjacking",
  check: "web.headers",
  category: "web",
  certainty: "confirmed",
  confidence: "high",
  title: () => "Schutz vor Einbettung (Clickjacking) fehlt",
  evaluate: fixed("low", "Weder X-Frame-Options noch CSP frame-ancestors gesetzt"),
  summary: (o) => `${o.asset} kann von fremden Seiten unsichtbar eingebettet werden.`,
  businessImpact: () => "Bei Seiten mit Login oder Formularen könnten Nutzer zu ungewollten Klicks verleitet werden.",
  recommendation: () => "„X-Frame-Options: SAMEORIGIN“ oder CSP „frame-ancestors 'self'“ setzen.",
  technicalDetails: (o) => `Keine Einbettungsbeschränkung in der Antwort von ${str(o, "url")}`,
  docs: [DOCS.owaspHeaders],
});

rule({
  id: "web.headers.version_disclosure",
  check: "web.headers",
  category: "web",
  certainty: "informational",
  confidence: "high",
  title: (o) => `Softwareversion wird preisgegeben (${str(o, "header")})`,
  evaluate: fixed("info", "Versionsangaben erleichtern Angreifern die Suche nach passenden Schwachstellen, sind aber selbst keine"),
  summary: (o) => `${o.asset} nennt die eingesetzte Software samt Version.`,
  businessImpact: () => "Angreifer erkennen schneller, ob veraltete Software im Einsatz ist.",
  recommendation: () => "Versionsangaben in Server-Headern deaktivieren und die Software aktuell halten.",
  technicalDetails: (o) => `${str(o, "header")}: ${str(o, "value")}`,
  docs: [DOCS.owaspHeaders],
});

rule({
  id: "web.cookies.insecure",
  check: "web.headers",
  category: "web",
  certainty: "confirmed",
  confidence: "medium",
  title: () => "Cookies ohne Sicherheitsattribute",
  evaluate: fixed("low", "Cookies ohne Secure/HttpOnly können unter Umständen mitgelesen oder per Skript ausgelesen werden"),
  summary: (o) => `${o.asset} setzt Cookies ohne die empfohlenen Schutzattribute.`,
  businessImpact: () => "Falls es sich um Sitzungs-Cookies handelt, steigt das Risiko einer Sitzungsübernahme.",
  recommendation: () => "Cookies mit „Secure“, „HttpOnly“ und „SameSite“ setzen.",
  technicalDetails: (o) => `Betroffene Cookie-Namen: ${(o.evidence.cookies as string[] | undefined)?.join(", ") ?? ""}`,
  docs: [DOCS.cookies],
});

rule({
  id: "web.security_txt.missing",
  check: "web.security_txt",
  category: "web",
  certainty: "informational",
  confidence: "high",
  title: () => "Keine security.txt hinterlegt",
  evaluate: fixed("info", "Sicherheitsforscher finden keinen Ansprechpartner für Meldungen"),
  summary: (o) => `${o.asset} bietet keine Kontaktinformation für Sicherheitsmeldungen (/.well-known/security.txt).`,
  businessImpact: () => "Hinweise auf Sicherheitslücken erreichen Sie eventuell nicht oder zu spät.",
  recommendation: () => "Datei /.well-known/security.txt mit Kontaktadresse und Ablaufdatum veröffentlichen.",
  technicalDetails: (o) => `GET https://${o.asset}/.well-known/security.txt → Status ${num(o, "status")}`,
  docs: [DOCS.securityTxt],
});

// ---------------------------------------------------------------------------
// Exposure (Shodan InternetDB)
// ---------------------------------------------------------------------------
export const RISKY_PORTS: Record<number, { service: string; severity: Severity; reason: string }> = {
  21: { service: "FTP", severity: "medium", reason: "FTP überträgt Zugangsdaten unverschlüsselt" },
  23: { service: "Telnet", severity: "high", reason: "Telnet ist unverschlüsselt und häufiges Ziel automatisierter Angriffe" },
  445: { service: "SMB (Windows-Dateifreigabe)", severity: "critical", reason: "SMB im Internet war Einfallstor u. a. für WannaCry" },
  139: { service: "NetBIOS", severity: "high", reason: "Windows-Netzwerkdienst, nicht für das Internet gedacht" },
  1433: { service: "Microsoft SQL Server", severity: "high", reason: "Datenbanken sollten nie direkt aus dem Internet erreichbar sein" },
  1521: { service: "Oracle Database", severity: "high", reason: "Datenbanken sollten nie direkt aus dem Internet erreichbar sein" },
  2375: { service: "Docker API (unverschlüsselt)", severity: "critical", reason: "Ungeschützte Docker-API erlaubt vollständige Übernahme des Hosts" },
  3306: { service: "MySQL/MariaDB", severity: "high", reason: "Datenbanken sollten nie direkt aus dem Internet erreichbar sein" },
  3389: { service: "Remotedesktop (RDP)", severity: "high", reason: "RDP ist eines der häufigsten Einfallstore für Ransomware" },
  5432: { service: "PostgreSQL", severity: "high", reason: "Datenbanken sollten nie direkt aus dem Internet erreichbar sein" },
  5900: { service: "VNC", severity: "high", reason: "Fernsteuerung, häufig schwach abgesichert" },
  6379: { service: "Redis", severity: "high", reason: "Redis ist standardmäßig ohne Authentifizierung" },
  9200: { service: "Elasticsearch", severity: "high", reason: "Häufige Ursache großer Datenlecks" },
  11211: { service: "Memcached", severity: "medium", reason: "Missbrauchbar für DDoS-Verstärkung, keine Authentifizierung" },
  27017: { service: "MongoDB", severity: "high", reason: "Häufige Ursache großer Datenlecks" },
  161: { service: "SNMP", severity: "medium", reason: "Kann Netzwerkinformationen preisgeben" },
  5985: { service: "WinRM", severity: "high", reason: "Windows-Fernverwaltung, nicht für das Internet gedacht" },
};

rule({
  id: "exposure.risky_service",
  check: "exposure.ports",
  category: "exposure",
  certainty: "potential",
  confidence: "medium",
  title: (o) => `${RISKY_PORTS[num(o, "port")]?.service ?? "Dienst"} öffentlich erreichbar (Port ${num(o, "port")})`,
  evaluate: (o) => {
    const p = RISKY_PORTS[num(o, "port")];
    return { severity: p?.severity ?? "medium", reasons: [p?.reason ?? "Kritischer Verwaltungsdienst öffentlich erreichbar", "Quelle: Shodan-Beobachtung (bis zu einer Woche alt), nicht selbst geprüft"] };
  },
  summary: (o) => `Laut Shodan ist auf ${o.asset} der Dienst ${RISKY_PORTS[num(o, "port")]?.service ?? ""} aus dem Internet erreichbar.`,
  businessImpact: (o) => `${RISKY_PORTS[num(o, "port")]?.reason ?? ""}. Solche Dienste werden täglich automatisiert angegriffen.`,
  recommendation: () => "Prüfen, ob der Dienst wirklich öffentlich erreichbar sein muss. Andernfalls per Firewall sperren oder nur über VPN zugänglich machen.",
  technicalDetails: (o) => `IP ${o.asset}, TCP-Port ${num(o, "port")} offen laut Shodan InternetDB (Stand: wöchentliche Aktualisierung). Hostnames: ${(o.evidence.hostnames as string[] | undefined)?.join(", ") ?? "–"}`,
  verificationSteps: (o) => `Aus einem externen Netz (nicht Firmennetz): nc -vz ${o.asset} ${num(o, "port")}`,
  docs: [],
});

rule({
  id: "exposure.cve_hint",
  check: "exposure.cves",
  category: "vulnerability",
  certainty: "potential",
  confidence: "low",
  title: (o) => `Hinweis auf ${str(o, "cve")}${f(o, "kev") ? " (aktiv ausgenutzt)" : ""}`,
  evaluate: (o) =>
    f(o, "kev")
      ? { severity: "high", reasons: [`${str(o, "cve")} steht im CISA-Katalog aktiv ausgenutzter Schwachstellen`, "Nur Versionshinweis aus Shodan – nicht bestätigt"] }
      : { severity: "medium", reasons: ["Shodan ordnet der erkannten Softwareversion diese CVE zu", "Nur Versionshinweis – Backports und Konfiguration können die Schwachstelle ausschließen"] },
  summary: (o) => `Shodan vermutet anhand der Softwareversion auf ${o.asset} die Schwachstelle ${str(o, "cve")}. Dies ist kein Nachweis.`,
  businessImpact: (o) =>
    f(o, "kev")
      ? "Diese Schwachstelle wird nachweislich von Angreifern ausgenutzt. Falls sie zutrifft, besteht dringender Handlungsbedarf."
      : "Falls die Vermutung zutrifft, könnten Angreifer die Schwachstelle ausnutzen.",
  recommendation: () => "IT-Dienstleister prüfen lassen, ob die betroffene Software in der angegebenen Version läuft und ob Sicherheitsupdates installiert sind.",
  technicalDetails: (o) => `IP ${o.asset}; CVE ${str(o, "cve")}; CPEs: ${(o.evidence.cpes as string[] | undefined)?.join(", ") ?? "–"}`,
  docs: [{ label: "NVD-Eintrag", url: "https://nvd.nist.gov/" }, DOCS.kev],
});

// ---------------------------------------------------------------------------
// Breach Intelligence
// ---------------------------------------------------------------------------
rule({
  id: "breach.accounts_exposed",
  check: "breach.domain",
  category: "breach",
  certainty: "confirmed",
  confidence: "high",
  title: (o) => `${num(o, "accountCount")} Firmenkonto${num(o, "accountCount") === 1 ? "" : "en"} in Datenleck „${str(o, "breachTitle")}“`,
  evaluate: (o) => {
    const classes = (o.facts.dataClasses as string[] | undefined) ?? [];
    const hasPasswords = classes.some((c) => /password/i.test(c));
    const ageDays = num(o, "breachAgeDays");
    const reasons: string[] = [];
    if (f(o, "isSpamList")) return { severity: "info", reasons: ["Spam-Liste: nur E-Mail-Adressen, keine Zugangsdaten"] };
    if (hasPasswords && ageDays <= 730) {
      reasons.push("Leck enthält Passwörter (gehasht oder im Klartext)", `Datenleck ist ${Math.round(ageDays / 30)} Monate alt (≤ 24 Monate)`);
      return { severity: "high", reasons };
    }
    if (hasPasswords) {
      reasons.push("Leck enthält Passwörter", `Datenleck ist älter als 2 Jahre (${Math.round(ageDays / 365)} Jahre)`);
      return { severity: "medium", reasons };
    }
    return { severity: "low", reasons: ["Keine Passwörter im Leck enthalten (nur z. B. Namen, E-Mail-Adressen)"] };
  },
  summary: (o) =>
    `Bei einem externen Dienst („${str(o, "breachTitle")}“) sind Daten abgeflossen. Darunter sind ${num(o, "accountCount")} E-Mail-Adressen Ihrer Domain. Das bedeutet nicht, dass Ihre eigenen Systeme betroffen sind.`,
  businessImpact: (o) => {
    const classes = (o.facts.dataClasses as string[] | undefined) ?? [];
    return classes.some((c) => /password/i.test(c))
      ? "Wurden dieselben Passwörter auch für Firmenkonten verwendet, könnten Angreifer sich damit anmelden. Ein Hinweis aus einem Datenleck ist kein Nachweis einer Kontoübernahme."
      : "Die Adressen können für gezielte Phishing-Mails genutzt werden.";
  },
  recommendation: () =>
    "1. Betroffene Mitarbeitende informieren. 2. Wenn das Firmenpasswort möglicherweise auch beim betroffenen Dienst genutzt wurde: Passwort ändern. 3. Mehr-Faktor-Anmeldung (MFA) für alle Firmenkonten prüfen. 4. Bei Auffälligkeiten aktive Sitzungen widerrufen und Anmeldeprotokolle prüfen.",
  technicalDetails: (o) =>
    `Quelle: Have I Been Pwned, Breach „${str(o, "breachKey")}“. Datum des Lecks: ${str(o, "breachDate") || "unbekannt"}. In HIBP aufgenommen: ${str(o, "addedDate") || "unbekannt"}. Betroffene Datenarten: ${((o.facts.dataClasses as string[]) ?? []).join(", ")}. Betroffene Konten sind in der Detailansicht (nur für Berechtigte) einsehbar.`,
  docs: [DOCS.hibp],
});

rule({
  id: "breach.stealer_log",
  check: "breach.stealer",
  category: "breach",
  certainty: "potential",
  confidence: "medium",
  title: (o) => `Hinweis auf Infostealer-Infektion (${num(o, "accountCount")} Konto/Konten)`,
  evaluate: fixed("high", "Infostealer-Logs stammen von infizierten Geräten und enthalten oft aktuelle Zugangsdaten und Sitzungs-Cookies"),
  summary: (o) =>
    `In Infostealer-Daten tauchen ${num(o, "accountCount")} E-Mail-Adressen Ihrer Domain auf. Das deutet auf ein mit Schadsoftware infiziertes Gerät hin (möglicherweise auch privat).`,
  businessImpact: () =>
    "Infostealer erfassen Passwörter und Anmeldesitzungen direkt vom Gerät. Ein solcher Hinweis ist ernst zu nehmen, beweist aber keine aktuelle Kontoübernahme.",
  recommendation: () =>
    "1. Betroffene Personen kontaktieren und Gerät prüfen lassen. 2. Passwörter der betroffenen Konten ändern. 3. Alle aktiven Sitzungen widerrufen. 4. MFA erzwingen. 5. Anmeldeprotokolle auf Auffälligkeiten prüfen.",
  technicalDetails: (o) => `Quelle: Have I Been Pwned Stealer-Logs (Domain-Abfrage). Betroffene Website-Domains: ${((o.evidence.websites as string[]) ?? []).slice(0, 20).join(", ")}`,
  docs: [DOCS.hibp],
});

rule({
  id: "breach.provider_domain_unverified",
  check: "breach.domain",
  category: "breach",
  certainty: "not_checkable",
  confidence: "high",
  title: () => "Datenleck-Prüfung noch nicht freigeschaltet",
  evaluate: fixed("info", "Der Datenanbieter verlangt eine eigene Domain-Verifikation, die noch aussteht"),
  summary: (o) => `Für ${o.asset} kann die Datenleck-Überwachung erst nach Freischaltung beim Datenanbieter erfolgen.`,
  businessImpact: () => "Bis zur Freischaltung erhalten Sie keine Hinweise auf bekannte Datenlecks mit Firmenadressen.",
  recommendation: () => "Keine Aktion Ihrerseits nötig – CyberSafe24 schließt die Freischaltung ab. Bei Rückfragen melden wir uns.",
  technicalDetails: (o) => `Domain ${o.asset} ist nicht in /api/v3/subscribeddomains des HIBP-Kontos enthalten.`,
  docs: [DOCS.hibp],
});

// ---------------------------------------------------------------------------
// Nuclei (nur nach ausdrücklicher Freigabe)
// ---------------------------------------------------------------------------
rule({
  id: "vuln.nuclei",
  check: "vuln.nuclei",
  category: "vulnerability",
  certainty: "confirmed",
  confidence: "medium",
  title: (o) => `${str(o, "name")}`,
  evaluate: (o) => {
    const s = str(o, "severity") as Severity;
    const valid: Severity[] = ["critical", "high", "medium", "low", "info"];
    return { severity: valid.includes(s) ? s : "info", reasons: [`Schweregrad laut freigegebenem Prüfmuster „${str(o, "templateId")}“`] };
  },
  summary: (o) => `Ein freigegebenes, nicht-destruktives Prüfmuster hat auf ${o.asset} angeschlagen: ${str(o, "name")}.`,
  businessImpact: (o) => str(o, "description") || "Siehe technische Details.",
  recommendation: (o) => str(o, "remediation") || "IT-Dienstleister prüfen lassen und gemäß Herstellerangaben beheben.",
  technicalDetails: (o) => `Template: ${str(o, "templateId")}\nTreffer: ${str(o, "matchedAt")}`,
  docs: [],
});

export const RULES: ReadonlyMap<string, RuleDefinition> = new Map(rules.map((r) => [r.id, r]));

export function getRule(id: string): RuleDefinition {
  const r = RULES.get(id);
  if (!r) throw new Error(`Unbekannte Regel: ${id}`);
  return r;
}
