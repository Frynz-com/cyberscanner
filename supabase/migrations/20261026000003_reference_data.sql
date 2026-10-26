-- Tarife (Preise netto, Stripe-Price-IDs kommen aus ENV-Variablen)
insert into public.plans (key, name, description, price_cents, stripe_price_env, limits, features, sort) values
  ('trial', 'Testphase', '14 Tage kostenlos testen – eingeschränkter Umfang', 0, null,
   '{"max_domains": 1, "max_subdomains_checked": 10, "min_scan_interval_hours": 168, "manual_scans_per_day": 2,
     "breach_monitoring": false, "partner_invites": 1, "reports": true, "vuln_scan": false}',
   array['1 Domain', 'Wöchentliche Prüfung', 'DNS-, E-Mail-, TLS- und Header-Prüfung'], 0),
  ('shield', 'Shield', 'Kontinuierliche Überwachung der externen Angriffsfläche', 24900, 'STRIPE_PRICE_SHIELD',
   '{"max_domains": 3, "max_subdomains_checked": 50, "min_scan_interval_hours": 24, "manual_scans_per_day": 10,
     "breach_monitoring": true, "partner_invites": 5, "reports": true, "vuln_scan": false}',
   array['Bis zu 3 Domains', 'Tägliche Prüfung', 'Subdomain-Erkennung', 'Datenleck-Überwachung (sofern aktiviert)',
         'IT-Dienstleister-Freigaben', 'Monatsbericht (PDF)'], 1),
  ('shield_care', 'Shield Care', 'Überwachung plus erweiterte Prüfungen und Notfall-Unterstützung', 49900, 'STRIPE_PRICE_SHIELD_CARE',
   '{"max_domains": 10, "max_subdomains_checked": 200, "min_scan_interval_hours": 12, "manual_scans_per_day": 30,
     "breach_monitoring": true, "partner_invites": 25, "reports": true, "vuln_scan": true}',
   array['Bis zu 10 Domains', 'Prüfung alle 12 Stunden', 'Alles aus Shield',
         'Autorisierte Schwachstellenprüfung (nach Freigabe)', 'Priorisierte Weiterleitung im Notfall'], 2);

insert into public.provider_integrations (key, label, kind, status) values
  ('dns', 'DNS-Sicherheitsprüfung', 'scanner', 'unknown'),
  ('tls', 'TLS-Zertifikatsprüfung', 'scanner', 'unknown'),
  ('http_headers', 'HTTP-Sicherheitsheader', 'scanner', 'unknown'),
  ('subfinder', 'Subdomain-Erkennung (Subfinder)', 'scanner', 'unknown'),
  ('ct_logs', 'Certificate Transparency', 'intel', 'unknown'),
  ('internetdb', 'Shodan InternetDB', 'intel', 'unknown'),
  ('hibp', 'Have I Been Pwned', 'breach', 'unknown'),
  ('nuclei', 'Nuclei (autorisierte Prüfung)', 'scanner', 'unknown'),
  ('cisa_kev', 'CISA KEV-Katalog', 'intel', 'unknown'),
  ('resend', 'E-Mail-Versand (Resend)', 'email', 'unknown'),
  ('stripe', 'Zahlungsabwicklung (Stripe)', 'billing', 'unknown');

-- Privater Storage-Bucket für Vorfall-Dateien und Berichte
insert into storage.buckets (id, name, public, file_size_limit)
values ('incident-files', 'incident-files', false, 10485760), ('reports', 'reports', false, 20971520)
on conflict (id) do nothing;
