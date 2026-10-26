export type MonitoringState = "active" | "paused" | "verification_required" | "scan_failed" | "pending_first_scan";

export interface MonitoringInput {
  domains: Array<{ verification_status: string; monitoring_enabled: boolean; last_scan_at: string | null; hasAuthorization: boolean }>;
  orgPaused: boolean;
  subscriptionActive: boolean;
  lastDomainJobStatus: string | null;
  isDemo?: boolean;
  missingIntegrations: string[];
}

export interface MonitoringStatus {
  state: MonitoringState;
  title: string;
  description: string;
  integrationMissing: boolean;
}

/** Ehrlicher Überwachungsstatus – ausschließlich aus Backend-Daten abgeleitet, kein "Protected"-Versprechen. */
export function computeMonitoringStatus(i: MonitoringInput): MonitoringStatus {
  const integrationMissing = i.missingIntegrations.length > 0;
  const verified = i.domains.filter((d) => d.verification_status === "verified");
  if (i.domains.length === 0 || verified.length === 0) {
    return { state: "verification_required", title: "Verifizierung erforderlich", description: i.domains.length === 0 ? "Fügen Sie eine Domain hinzu, um die Überwachung zu starten." : "Bitte bestätigen Sie per DNS-Eintrag, dass die Domain Ihnen gehört.", integrationMissing };
  }
  if (!verified.some((d) => d.hasAuthorization)) {
    return { state: "verification_required", title: "Freigabe erforderlich", description: "Erteilen Sie die Prüfberechtigung, damit wir mit der Überwachung beginnen können.", integrationMissing };
  }
  if (i.orgPaused || !i.subscriptionActive || !verified.some((d) => d.monitoring_enabled)) {
    return { state: "paused", title: "Überwachung pausiert", description: !i.subscriptionActive ? "Ihr Abonnement ist nicht aktiv – es finden keine Prüfungen statt." : "Die regelmäßige Prüfung ist derzeit ausgeschaltet.", integrationMissing };
  }
  if (i.lastDomainJobStatus === "failed") {
    return { state: "scan_failed", title: "Letzte Prüfung fehlgeschlagen", description: "Die letzte Prüfung konnte nicht abgeschlossen werden. Wir versuchen es automatisch erneut.", integrationMissing };
  }
  if (!verified.some((d) => d.last_scan_at)) {
    return { state: "pending_first_scan", title: "Erste Prüfung ausstehend", description: "Die Überwachung ist eingerichtet. Die erste Prüfung startet in Kürze.", integrationMissing };
  }
  return { state: "active", title: "Überwachung aktiv", description: verified.length === 1 ? "1 Domain wird regelmäßig geprüft." : `${verified.length} Domains werden regelmäßig geprüft.`, integrationMissing };
}
