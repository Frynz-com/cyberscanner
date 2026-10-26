-- Häufige, leichte Threat-Intel-Abfragen (Infostealer, Ransomware-Leakseiten, Datenlecks, Phishing-Domains)
alter table public.scan_jobs drop constraint if exists scan_jobs_kind_check;
alter table public.scan_jobs add constraint scan_jobs_kind_check
  check (kind in ('domain_scan', 'reverify', 'public_check', 'verify_domain', 'maintenance', 'intel_watch'));
alter table public.domains add column if not exists next_intel_at timestamptz;

update public.plans set limits = limits || '{"intel_interval_hours": 24}'::jsonb where key = 'trial';
update public.plans set limits = limits || '{"intel_interval_hours": 6}'::jsonb where key = 'shield';
update public.plans set limits = limits || '{"intel_interval_hours": 1}'::jsonb where key = 'shield_care';
