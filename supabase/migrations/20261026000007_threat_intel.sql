-- Neue Kategorie "brand" (nachgemachte Domains) und neue Datenquellen
alter table public.findings drop constraint if exists findings_category_check;
alter table public.findings add constraint findings_category_check
  check (category in ('email', 'dns', 'tls', 'web', 'exposure', 'vulnerability', 'breach', 'asset', 'brand'));

insert into public.provider_integrations (key, label, kind, status) values
  ('hudsonrock', 'Hudson Rock (Infostealer-Hinweise)', 'breach', 'unknown'),
  ('ransomware_live', 'ransomware.live (Leakseiten)', 'intel', 'unknown'),
  ('lookalike', 'Nachgemachte Domains (Phishing)', 'scanner', 'unknown')
on conflict (key) do nothing;
