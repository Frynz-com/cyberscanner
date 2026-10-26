import { Document, Page, StyleSheet, Text, View } from "@react-pdf/renderer";
import type { ReportFinding, ReportSnapshot } from "@/lib/core/report-data";

/** Standard-PDF-Schriften (WinAnsi) kennen manche Unicode-Zeichen nicht – sicher ersetzen. */
export function pdfText(s: string | null | undefined): string {
  return (s ?? "")
    .replace(/≤/g, "<=")
    .replace(/≥/g, ">=")
    .replace(/→/g, "->")
    .replace(/[✓✔]/g, "+")
    .replace(/[^\n\t\u0020-\u00ff\u2013\u2014\u2018\u2019\u201a\u201c\u201d\u201e\u2022\u2026\u20ac]/g, "?");
}

const C = { ink: "#1f2329", muted: "#6b7280", line: "#e5e7eb", soft: "#f5f6f8", brand: "#0f766e", critical: "#c2410c", high: "#ea580c", medium: "#ca8a04", low: "#2563eb", info: "#9ca3af", ok: "#059669" };
const SEV: Record<string, { label: string; color: string }> = {
  critical: { label: "Kritisch", color: "#b91c1c" },
  high: { label: "Hoch", color: C.high },
  medium: { label: "Mittel", color: C.medium },
  low: { label: "Niedrig", color: C.low },
  info: { label: "Info", color: C.info },
};
const CERT: Record<string, string> = { confirmed: "Bestätigter Befund", potential: "Mögliches Risiko", informational: "Informationshinweis", not_checkable: "Nicht prüfbar" };
const STATUS: Record<string, string> = { new: "Neu", investigating: "In Prüfung", action_required: "Handlungsbedarf", resolved: "Behoben", accepted_risk: "Akzeptiert", false_positive: "Fehlalarm" };
const ACTION: Record<string, string> = { open: "Offen", in_progress: "In Bearbeitung", fixed_pending_verification: "Umgesetzt – Nachprüfung", still_open: "Weiterhin offen" };

const s = StyleSheet.create({
  page: { paddingTop: 56, paddingBottom: 56, paddingHorizontal: 48, fontSize: 9.5, color: C.ink, fontFamily: "Helvetica", lineHeight: 1.45 },
  header: { position: "absolute", top: 24, left: 48, right: 48, flexDirection: "row", justifyContent: "space-between", fontSize: 8, color: C.muted },
  footer: { position: "absolute", bottom: 24, left: 48, right: 48, flexDirection: "row", justifyContent: "space-between", fontSize: 8, color: C.muted, borderTopWidth: 0.5, borderTopColor: C.line, paddingTop: 6 },
  h1: { fontSize: 20, fontFamily: "Helvetica-Bold", marginBottom: 10, lineHeight: 1.25 },
  h2: { fontSize: 13, fontFamily: "Helvetica-Bold", marginBottom: 8, marginTop: 4, lineHeight: 1.3 },
  h3: { fontSize: 10.5, fontFamily: "Helvetica-Bold", marginBottom: 3, lineHeight: 1.35 },
  muted: { color: C.muted },
  kpiRow: { flexDirection: "row", gap: 8, marginVertical: 10 },
  kpi: { flex: 1, borderWidth: 0.5, borderColor: C.line, borderRadius: 4, padding: 10 },
  kpiValue: { fontSize: 18, fontFamily: "Helvetica-Bold", lineHeight: 1.2, marginBottom: 2 },
  kpiLabel: { fontSize: 8, color: C.muted },
  tableRow: { flexDirection: "row", borderBottomWidth: 0.5, borderBottomColor: C.line, paddingVertical: 4 },
  th: { fontFamily: "Helvetica-Bold", fontSize: 8, color: C.muted },
  card: { borderWidth: 0.5, borderColor: C.line, borderRadius: 4, padding: 10, marginBottom: 8 },
  pill: { fontSize: 7.5, lineHeight: 1.2, paddingHorizontal: 5, paddingVertical: 1.5, borderRadius: 6, color: "#fff", marginRight: 4 },
  callout: { backgroundColor: "#ecfdf5", borderRadius: 4, padding: 10, marginVertical: 8 },
  demo: { position: "absolute", top: 330, left: 60, fontSize: 90, lineHeight: 1, color: "#7c3aed", opacity: 0.08, transform: "rotate(-30deg)", fontFamily: "Helvetica-Bold" },
});

const d = (iso: string | null) => (iso ? new Date(iso).toLocaleDateString("de-DE", { timeZone: "Europe/Berlin" }) : "–");

function Chrome({ snap }: { snap: ReportSnapshot }) {
  return (
    <>
      {snap.isDemo && <Text style={s.demo} fixed>DEMO</Text>}
      <View style={s.header} fixed>
        <Text>CyberSafe24 Shield · Sicherheitsbericht</Text>
        <Text>{pdfText(snap.organization.name)}{snap.isDemo ? " · DEMO – synthetische Daten" : ""}</Text>
      </View>
      <View style={s.footer} fixed>
        <Text>Vertraulich · CyberSafe24 GmbH · erstellt am {d(snap.generatedAt)}</Text>
        <Text render={({ pageNumber, totalPages }) => `Seite ${pageNumber} von ${totalPages}`} />
      </View>
    </>
  );
}

function SevPill({ sev }: { sev: string }) {
  return <Text style={[s.pill, { backgroundColor: SEV[sev]?.color ?? C.info }]}>{SEV[sev]?.label ?? sev}</Text>;
}

function FindingCard({ f, appendix }: { f: ReportFinding; appendix?: boolean }) {
  return (
    <View style={s.card} wrap={false}>
      <View style={{ flexDirection: "row", alignItems: "center", marginBottom: 3 }}>
        <SevPill sev={f.severity} />
        <Text style={{ fontSize: 7.5, color: C.muted }}>{CERT[f.certainty]} · {STATUS[f.status] ?? f.status} · Priorität {f.priority}/100</Text>
      </View>
      <Text style={s.h3}>{pdfText(f.title)}</Text>
      <Text style={[s.muted, { fontSize: 8, marginBottom: 3 }]}>Asset: {pdfText(f.asset)} · erkannt {d(f.firstSeen)} · zuletzt bestätigt {d(f.lastSeen)}</Text>
      {appendix ? (
        <>
          <Text style={{ fontFamily: "Courier", fontSize: 7.5 }}>{pdfText(f.technicalDetails)}</Text>
          <Text style={{ fontSize: 7.5, color: C.muted, marginTop: 3 }}>Regel: {f.ruleId} · Quelle: {f.source}</Text>
        </>
      ) : (
        <>
          <Text>{pdfText(f.summary)}</Text>
          <Text style={{ marginTop: 3 }}><Text style={{ fontFamily: "Helvetica-Bold" }}>Empfehlung: </Text>{pdfText(f.recommendation)}</Text>
        </>
      )}
    </View>
  );
}

export function ReportDocument({ snap }: { snap: ReportSnapshot }) {
  const c = snap.counts;
  const delta = (now: number, prev: number) => (now === prev ? "unverändert" : now > prev ? `+${now - prev}` : `${now - prev}`);
  return (
    <Document title={`Sicherheitsbericht ${snap.organization.name}`} author="CyberSafe24 GmbH" language="de">
      {/* Deckblatt */}
      <Page size="A4" style={[s.page, { paddingTop: 140 }]}>
        {snap.isDemo && <Text style={s.demo}>DEMO</Text>}
        <Text style={{ fontSize: 11, color: C.brand, fontFamily: "Helvetica-Bold", letterSpacing: 1 }}>CYBERSAFE24 SHIELD</Text>
        <Text style={{ fontSize: 30, fontFamily: "Helvetica-Bold", marginTop: 16, lineHeight: 1.2 }}>Sicherheitsbericht</Text>
        <Text style={{ fontSize: 16, marginTop: 10, lineHeight: 1.3 }}>{pdfText(snap.organization.name)}</Text>
        <Text style={{ fontSize: 11, color: C.muted, marginTop: 24 }}>Berichtszeitraum: {d(snap.period.start)} – {d(snap.period.end)}</Text>
        <Text style={{ fontSize: 11, color: C.muted }}>Erstellt am: {d(snap.generatedAt)}</Text>
        {snap.isDemo && <Text style={{ marginTop: 24, color: "#7c3aed", fontFamily: "Helvetica-Bold" }}>DEMO-BERICHT – alle Inhalte sind synthetisch und dienen nur der Vorführung.</Text>}
        <View style={{ position: "absolute", bottom: 60, left: 48, right: 48 }}>
          <Text style={{ fontSize: 8, color: C.muted }}>
            Dieser Bericht fasst die Ergebnisse der von Ihnen freigegebenen externen Prüfungen zusammen. Er stellt keine vollständige Sicherheitsprüfung, kein Penetrationstest und keine Zertifizierung dar.
          </Text>
        </View>
      </Page>

      {/* Zusammenfassung */}
      <Page size="A4" style={s.page}>
        <Chrome snap={snap} />
        <Text style={s.h1}>Zusammenfassung</Text>
        <View style={s.callout}>
          <Text>Im Berichtszeitraum wurden <Text style={{ fontFamily: "Helvetica-Bold" }}>{c.newInPeriod} neue Befunde</Text> erkannt und <Text style={{ fontFamily: "Helvetica-Bold" }}>{c.verifiedInPeriod} Befunde erfolgreich nachgeprüft</Text> (technisch bestätigte Behebung). Insgesamt fanden {snap.scansInPeriod} vollständige Prüfungen statt.</Text>
        </View>
        <View style={s.kpiRow}>
          <View style={s.kpi}><Text style={s.kpiValue}>{c.open}</Text><Text style={s.kpiLabel}>Offene Befunde</Text></View>
          <View style={s.kpi}><Text style={[s.kpiValue, { color: (c.openBySeverity.critical ?? 0) + (c.openBySeverity.high ?? 0) > 0 ? "#b91c1c" : C.ink }]}>{(c.openBySeverity.critical ?? 0) + (c.openBySeverity.high ?? 0)}</Text><Text style={s.kpiLabel}>davon kritisch/hoch</Text></View>
          <View style={s.kpi}><Text style={s.kpiValue}>{c.newInPeriod}</Text><Text style={s.kpiLabel}>Neu im Zeitraum</Text></View>
          <View style={s.kpi}><Text style={[s.kpiValue, { color: C.ok }]}>{c.resolvedInPeriod}</Text><Text style={s.kpiLabel}>Behoben im Zeitraum</Text></View>
        </View>
        <Text style={s.h2}>Entwicklung gegenüber Vorperiode</Text>
        <View style={[s.tableRow]}><Text style={[s.th, { flex: 2 }]}>Kennzahl</Text><Text style={[s.th, { flex: 1 }]}>Vorperiode</Text><Text style={[s.th, { flex: 1 }]}>Berichtszeitraum</Text><Text style={[s.th, { flex: 1 }]}>Veränderung</Text></View>
        <View style={s.tableRow}><Text style={{ flex: 2 }}>Neu erkannte Befunde</Text><Text style={{ flex: 1 }}>{c.previousPeriod.newInPeriod}</Text><Text style={{ flex: 1 }}>{c.newInPeriod}</Text><Text style={{ flex: 1 }}>{delta(c.newInPeriod, c.previousPeriod.newInPeriod)}</Text></View>
        <View style={s.tableRow}><Text style={{ flex: 2 }}>Behobene Befunde</Text><Text style={{ flex: 1 }}>{c.previousPeriod.resolvedInPeriod}</Text><Text style={{ flex: 1 }}>{c.resolvedInPeriod}</Text><Text style={{ flex: 1 }}>{delta(c.resolvedInPeriod, c.previousPeriod.resolvedInPeriod)}</Text></View>
        <Text style={[s.h2, { marginTop: 14 }]}>Offene Befunde nach Schweregrad</Text>
        <View style={{ flexDirection: "row", gap: 6 }}>
          {(["critical", "high", "medium", "low", "info"] as const).map((k) => (
            <View key={k} style={[s.kpi, { borderLeftWidth: 3, borderLeftColor: SEV[k].color }]}><Text style={{ fontSize: 14, fontFamily: "Helvetica-Bold", lineHeight: 1.2, marginBottom: 2 }}>{c.openBySeverity[k] ?? 0}</Text><Text style={s.kpiLabel}>{SEV[k].label}</Text></View>
          ))}
        </View>
        {c.acceptedRisk > 0 && <Text style={[s.muted, { marginTop: 6 }]}>{c.acceptedRisk} Befund(e) wurden bewusst als Risiko akzeptiert.</Text>}

        <Text style={[s.h2, { marginTop: 16 }]}>Monitoring-Abdeckung</Text>
        {snap.domains.map((dm) => (
          <Text key={dm.hostname}>• {dm.hostname} – {dm.status === "verified" ? "verifiziert" : dm.status} · {dm.assetCount} Assets · zuletzt geprüft {d(dm.lastScanAt)}</Text>
        ))}
        <View style={{ marginTop: 6 }}>
          <View style={s.tableRow}><Text style={[s.th, { flex: 2 }]}>Prüfmodul</Text><Text style={[s.th, { flex: 1 }]}>Status</Text><Text style={[s.th, { flex: 1 }]}>Letzter Lauf</Text><Text style={[s.th, { flex: 2 }]}>Hinweis</Text></View>
          {snap.coverage.map((cv) => (
            <View key={cv.adapter} style={s.tableRow}>
              <Text style={{ flex: 2 }}>{pdfText(cv.adapter)}</Text>
              <Text style={{ flex: 1 }}>{{ ok: "Geprüft", partial: "Teilweise", error: "Fehler", unavailable: "Nicht verfügbar", not_authorized: "Nicht freigegeben", skipped: "Übersprungen" }[cv.status] ?? cv.status}</Text>
              <Text style={{ flex: 1 }}>{d(cv.lastRun)}</Text>
              <Text style={{ flex: 2, fontSize: 7.5, color: C.muted }}>{pdfText(cv.message ?? "")}</Text>
            </View>
          ))}
        </View>
      </Page>

      {/* Ergebnisse */}
      <Page size="A4" style={s.page}>
        <Chrome snap={snap} />
        <Text style={s.h1}>Wichtigste offene Ergebnisse</Text>
        {snap.topOpen.length === 0 ? <Text style={s.muted}>Keine offenen Befunde.</Text> : snap.topOpen.map((f) => <FindingCard key={f.id} f={f} />)}

        <Text style={[s.h2, { marginTop: 10 }]} break={snap.topOpen.length > 4}>Neu erkannte Risiken im Zeitraum ({snap.newFindings.length})</Text>
        {snap.newFindings.length === 0 ? <Text style={s.muted}>Keine neuen Befunde im Berichtszeitraum.</Text> : snap.newFindings.map((f) => (
          <View key={f.id} style={s.tableRow} wrap={false}><Text style={{ width: 52 }}>{SEV[f.severity]?.label}</Text><Text style={{ flex: 3 }}>{pdfText(f.title)}</Text><Text style={{ flex: 2, color: C.muted }}>{pdfText(f.asset)}</Text><Text style={{ width: 55 }}>{d(f.firstSeen)}</Text></View>
        ))}

        <Text style={[s.h2, { marginTop: 14 }]}>Behobene Risiken ({snap.resolvedFindings.length})</Text>
        {snap.resolvedFindings.length === 0 ? <Text style={s.muted}>Im Berichtszeitraum wurden keine Befunde geschlossen.</Text> : snap.resolvedFindings.map((f) => (
          <View key={f.id} style={s.tableRow} wrap={false}><Text style={{ flex: 3 }}>{pdfText(f.title)}</Text><Text style={{ flex: 2, color: C.muted }}>{pdfText(f.asset)}</Text><Text style={{ flex: 2, color: f.verificationState === "verified_fixed" ? C.ok : C.muted }}>{f.verificationState === "verified_fixed" ? "Technisch bestätigt" : "Als behoben markiert (unbestätigt)"}</Text></View>
        ))}

        <Text style={[s.h2, { marginTop: 14 }]}>Noch offene Maßnahmen</Text>
        {snap.openActions.length === 0 ? <Text style={s.muted}>Keine offenen Maßnahmen bei IT-Dienstleistern.</Text> : snap.openActions.map((a, i) => (
          <View key={i} style={s.tableRow} wrap={false}><Text style={{ flex: 3 }}>{pdfText(a.findingTitle)}</Text><Text style={{ flex: 2 }}>{pdfText(a.partner ?? "–")}</Text><Text style={{ flex: 2 }}>{ACTION[a.status] ?? a.status}</Text></View>
        ))}
      </Page>

      {/* Methodik */}
      <Page size="A4" style={s.page}>
        <Chrome snap={snap} />
        <Text style={s.h1}>Methodik und Grenzen der Prüfung</Text>
        <Text style={s.h3}>Was geprüft wird</Text>
        <Text>CyberSafe24 Shield prüft ausschließlich von außen sichtbare Eigenschaften der verifizierten Domains im Rahmen der schriftlich erteilten Freigabe: DNS- und E-Mail-Konfiguration (SPF, DMARC, DKIM-Hinweise, DNSSEC, CAA), TLS-Zertifikate und -Protokolle, HTTP-Sicherheitsheader, passiv ermittelte Subdomains (ProjectDiscovery Subfinder, Certificate-Transparency-Logs) sowie – sofern lizenziert und aktiviert – bekannte offene Dienste (Shodan InternetDB) und bekannte Datenlecks (Have I Been Pwned).</Text>
        <Text style={[s.h3, { marginTop: 10 }]}>Bewertung</Text>
        <Text>Jeder Befund wird nach einem deterministischen, nachvollziehbaren Regelwerk bewertet. Der Prioritätswert ergibt sich aus Schweregrad × Gewissheit zuzüglich begründeter Zuschläge (z. B. Hauptdomain, aktiv ausgenutzte Schwachstelle laut CISA KEV). Es werden vier Gewissheitsstufen unterschieden: bestätigter Befund (direkt technisch festgestellt), mögliches Risiko (Hinweis aus Datenquellen oder Versionsangaben, nicht selbst bestätigt), Informationshinweis und nicht prüfbar.</Text>
        <Text style={[s.h3, { marginTop: 10 }]}>Nachprüfung</Text>
        <Text>Ein Befund gilt nur dann als „technisch bestätigt behoben“, wenn die zuständige Prüfung für das betroffene System vollständig durchgeführt wurde und das Problem nicht mehr festgestellt hat. Vom Kunden als behoben markierte Befunde werden bis zur Bestätigung als unbestätigt ausgewiesen.</Text>
        <Text style={[s.h3, { marginTop: 10 }]}>Grenzen</Text>
        <Text>• Keine Prüfung interner Systeme, Endgeräte, Anwendungslogik oder Konfigurationen hinter Anmeldungen.</Text>
        <Text>• Keine Penetrationstests, keine Ausnutzung von Schwachstellen, keine Last- oder Brute-Force-Tests.</Text>
        <Text>• Daten Dritter (z. B. Shodan, HIBP) können veraltet oder unvollständig sein; CVE-Hinweise beruhen auf Versionsangaben und sind keine Bestätigung einer Schwachstelle.</Text>
        <Text>• Ein Hinweis auf ein Datenleck ist kein Nachweis, dass ein Konto aktuell kompromittiert ist.</Text>
        <Text>• Nicht verfügbare oder nicht lizenzierte Prüfmodule sind in der Monitoring-Abdeckung ausgewiesen; für sie liegen keine Ergebnisse vor.</Text>
        <Text>• Der Bericht ist keine Zertifizierung und bescheinigt keine vollständige Sicherheit.</Text>
        <Text style={[s.muted, { marginTop: 12, fontSize: 8 }]}>Datenquellen u. a.: Have I Been Pwned (CC BY 4.0, haveibeenpwned.com), CISA Known Exploited Vulnerabilities Catalog, crt.sh / SSLMate Cert Spotter, ProjectDiscovery Subfinder (MIT).</Text>
      </Page>

      {/* Anhang */}
      <Page size="A4" style={s.page}>
        <Chrome snap={snap} />
        <Text style={s.h1}>Technischer Anhang</Text>
        <Text style={[s.muted, { marginBottom: 8 }]}>Technische Details der offenen und im Zeitraum neu erkannten Befunde für Ihren IT-Dienstleister.</Text>
        {[...snap.topOpen, ...snap.newFindings.filter((n) => !snap.topOpen.some((t) => t.id === n.id))].slice(0, 40).map((f) => <FindingCard key={f.id} f={f} appendix />)}
      </Page>
    </Document>
  );
}
