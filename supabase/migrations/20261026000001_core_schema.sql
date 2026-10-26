-- CyberSafe24 Shield – Kernschema
-- Grundprinzipien:
--  * Jede mandantenbezogene Tabelle trägt org_id NOT NULL.
--  * Lesen: authentifizierte Mitglieder über RLS.
--  * Schreiben: ausschließlich serverseitig (Service Role) nach expliziter Rechteprüfung.
--    Für "authenticated" existieren bewusst keine INSERT/UPDATE/DELETE-Policies
--    (Ausnahme: eigenes Profil).
--  * Demo-Mandanten sind per Flag und Constraints strikt von echten Mandanten getrennt.

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------------
-- Enums
-- ---------------------------------------------------------------------------
create type public.finding_status as enum
  ('new', 'investigating', 'action_required', 'resolved', 'accepted_risk', 'false_positive');
create type public.finding_severity as enum ('critical', 'high', 'medium', 'low', 'info');
-- bestätigter Befund / mögliches Risiko / Informationshinweis / nicht prüfbar
create type public.finding_certainty as enum ('confirmed', 'potential', 'informational', 'not_checkable');
create type public.confidence_level as enum ('high', 'medium', 'low');
create type public.job_status as enum ('queued', 'running', 'succeeded', 'failed', 'cancelled');
create type public.domain_verification_status as enum ('pending', 'verified', 'failed', 'expired');

-- ---------------------------------------------------------------------------
-- Benutzer, Rollen, Organisationen
-- ---------------------------------------------------------------------------
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text check (char_length(full_name) <= 120),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
comment on table public.profiles is 'users: öffentliche Profildaten zu auth.users';

create table public.roles (
  key text primary key,
  label text not null,
  rank int not null unique,
  description text not null
);
insert into public.roles (key, label, rank, description) values
  ('owner', 'Inhaber', 100, 'Volle Kontrolle inkl. Abrechnung und Löschung'),
  ('admin', 'Administrator', 80, 'Domains, Scans, Freigaben und Mitglieder verwalten'),
  ('member', 'Mitglied', 50, 'Befunde bearbeiten, Prüfungen anstoßen, Vorfälle melden'),
  ('viewer', 'Lesezugriff', 10, 'Nur lesen');

create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 120),
  industry text check (char_length(industry) <= 80),
  employee_range text check (employee_range in ('1-9', '10-49', '50-249', '250-999', '1000+')),
  contact_email text check (contact_email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  contact_phone text check (char_length(contact_phone) <= 40),
  is_demo boolean not null default false,
  monitoring_paused boolean not null default false,
  onboarding_step int not null default 2,
  data_retention_days int not null default 365 check (data_retention_days between 30 and 1825),
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deleted_at timestamptz
);

create table public.memberships (
  org_id uuid not null references public.organizations (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  role text not null references public.roles (key),
  created_at timestamptz not null default now(),
  primary key (org_id, user_id)
);
create index memberships_user_idx on public.memberships (user_id);

create table public.platform_admins (
  user_id uuid primary key references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Hilfsfunktionen für RLS (security definer, um Rekursion zu vermeiden)
-- ---------------------------------------------------------------------------
create or replace function public.is_org_member(p_org uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.memberships m
    join public.organizations o on o.id = m.org_id
    where m.org_id = p_org and m.user_id = (select auth.uid()) and o.deleted_at is null
  );
$$;

create or replace function public.org_role_rank(p_org uuid)
returns int language sql stable security definer set search_path = '' as $$
  select coalesce(max(r.rank), 0) from public.memberships m
  join public.roles r on r.key = m.role
  where m.org_id = p_org and m.user_id = (select auth.uid());
$$;

create or replace function public.is_platform_admin()
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.platform_admins where user_id = (select auth.uid()));
$$;

-- ---------------------------------------------------------------------------
-- Domains & Verifikation
-- ---------------------------------------------------------------------------
create table public.domains (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  hostname text not null check (
    hostname ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$'
    and char_length(hostname) <= 253
  ),
  is_demo boolean not null default false,
  verification_status public.domain_verification_status not null default 'pending',
  verified_at timestamptz,
  verification_last_checked_at timestamptz,
  monitoring_enabled boolean not null default true,
  scan_interval_hours int not null default 24 check (scan_interval_hours between 6 and 744),
  next_scan_at timestamptz,
  last_scan_at timestamptz,
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  unique (org_id, hostname),
  -- Demo-Domains müssen auf die reservierte TLD .example enden (RFC 2606) und umgekehrt
  constraint demo_domain_tld check (is_demo = (hostname like '%.example'))
);
create index domains_org_idx on public.domains (org_id);
create index domains_next_scan_idx on public.domains (next_scan_at) where verification_status = 'verified' and monitoring_enabled;

create table public.verification_challenges (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  domain_id uuid not null references public.domains (id) on delete cascade,
  record_name text not null,
  token text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '14 days',
  attempts int not null default 0,
  last_checked_at timestamptz,
  last_result text,
  consumed_at timestamptz
);
create index verification_challenges_domain_idx on public.verification_challenges (domain_id);

-- ---------------------------------------------------------------------------
-- Scan-Berechtigungen (schriftliche Autorisierung)
-- ---------------------------------------------------------------------------
create table public.scan_authorizations (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  domain_id uuid not null references public.domains (id) on delete cascade,
  -- passive: öffentliche Datenquellen; config: schonende Konfigurationsprüfung (wie Browseraufruf);
  -- vuln_scan: freigegebene, nicht-destruktive Nuclei-Templates (nur nach gesonderter Freigabe)
  scopes text[] not null check (scopes <@ array['passive', 'config', 'vuln_scan']::text[] and cardinality(scopes) > 0),
  include_subdomains boolean not null default true,
  statement_version text not null,
  statement_sha256 text not null,
  signer_name text not null check (char_length(signer_name) between 2 and 120),
  signer_role text not null check (char_length(signer_role) between 2 and 120),
  granted_by uuid references auth.users (id) on delete set null,
  ip_hash text,
  user_agent text,
  granted_at timestamptz not null default now(),
  valid_until timestamptz not null default now() + interval '1 year',
  revoked_at timestamptz,
  revoked_by uuid references auth.users (id) on delete set null
);
create index scan_authorizations_domain_idx on public.scan_authorizations (domain_id);

-- ---------------------------------------------------------------------------
-- Assets
-- ---------------------------------------------------------------------------
create table public.assets (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  domain_id uuid not null references public.domains (id) on delete cascade,
  kind text not null check (kind in ('domain', 'subdomain', 'ip')),
  value text not null check (char_length(value) <= 253),
  sources text[] not null default '{}',
  is_demo boolean not null default false,
  is_active boolean not null default true,
  -- aktive Schwachstellenprüfung nur nach expliziter Freigabe pro Asset
  vuln_scan_approved boolean not null default false,
  metadata jsonb not null default '{}',
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  unique (org_id, kind, value)
);
create index assets_domain_idx on public.assets (domain_id);

-- ---------------------------------------------------------------------------
-- Job-Queue
-- ---------------------------------------------------------------------------
create table public.scan_jobs (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references public.organizations (id) on delete cascade, -- NULL nur für öffentliche Kurzchecks
  domain_id uuid references public.domains (id) on delete cascade,
  kind text not null check (kind in ('domain_scan', 'reverify', 'public_check', 'verify_domain', 'maintenance')),
  trigger text not null check (trigger in ('manual', 'schedule', 'onboarding', 'reverify', 'public', 'system', 'partner')),
  status public.job_status not null default 'queued',
  priority int not null default 0,
  payload jsonb not null default '{}',
  idempotency_key text not null unique,
  attempts int not null default 0,
  max_attempts int not null default 3,
  run_after timestamptz not null default now(),
  locked_by text,
  locked_at timestamptz,
  heartbeat_at timestamptz,
  started_at timestamptz,
  finished_at timestamptz,
  cancel_requested boolean not null default false,
  error text,
  summary jsonb,
  requested_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  constraint org_required check (kind = 'public_check' or kind = 'maintenance' or org_id is not null)
);
create index scan_jobs_claim_idx on public.scan_jobs (status, run_after, priority desc, created_at) where status = 'queued';
create index scan_jobs_org_idx on public.scan_jobs (org_id, created_at desc);

create table public.scan_results (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null references public.scan_jobs (id) on delete cascade,
  org_id uuid references public.organizations (id) on delete cascade,
  domain_id uuid references public.domains (id) on delete cascade,
  adapter text not null,
  status text not null check (status in ('ok', 'partial', 'error', 'unavailable', 'skipped', 'not_authorized')),
  started_at timestamptz not null,
  finished_at timestamptz not null,
  duration_ms int not null,
  targets text[] not null default '{}',
  checks text[] not null default '{}',
  observation_count int not null default 0,
  message text,
  data jsonb not null default '{}'
);
create index scan_results_org_idx on public.scan_results (org_id, finished_at desc);
create index scan_results_job_idx on public.scan_results (job_id);

-- ---------------------------------------------------------------------------
-- Findings
-- ---------------------------------------------------------------------------
create table public.findings (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  domain_id uuid references public.domains (id) on delete cascade,
  asset_id uuid references public.assets (id) on delete set null,
  asset_value text not null,
  fingerprint text not null,
  rule_id text not null,
  check_key text not null,
  category text not null check (category in ('email', 'dns', 'tls', 'web', 'exposure', 'vulnerability', 'breach', 'asset')),
  source text not null,
  source_ref text,
  title text not null,
  summary text not null,
  business_impact text not null,
  recommendation text not null,
  technical_details text not null,
  verification_steps text,
  docs jsonb not null default '[]',
  evidence jsonb not null default '{}',
  severity public.finding_severity not null,
  certainty public.finding_certainty not null,
  confidence public.confidence_level not null,
  priority_score int not null default 0 check (priority_score between 0 and 100),
  priority_reasons jsonb not null default '[]',
  status public.finding_status not null default 'new',
  -- Nachprüfung: unverified = vom Kunden als behoben markiert, aber nicht technisch bestätigt
  verification_state text check (verification_state in ('unverified', 'verified_fixed', 'still_present')),
  is_demo boolean not null default false,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  resolved_at timestamptz,
  reopened_count int not null default 0,
  last_job_id uuid references public.scan_jobs (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (org_id, fingerprint)
);
create index findings_org_status_idx on public.findings (org_id, status, priority_score desc);
create index findings_domain_idx on public.findings (domain_id);

create table public.finding_events (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  finding_id uuid not null references public.findings (id) on delete cascade,
  type text not null check (type in (
    'detected', 'seen_again', 'reappeared', 'status_changed', 'shared_with_partner', 'partner_update',
    'reverify_requested', 'verified_fixed', 'still_present', 'comment', 'severity_changed', 'auto_resolved')),
  from_status public.finding_status,
  to_status public.finding_status,
  actor_type text not null check (actor_type in ('user', 'system', 'partner')),
  actor_id uuid,
  actor_label text,
  message text check (char_length(message) <= 4000),
  data jsonb not null default '{}',
  created_at timestamptz not null default now()
);
create index finding_events_finding_idx on public.finding_events (finding_id, created_at);
create index finding_events_org_idx on public.finding_events (org_id, created_at desc);

-- Personenbezogene Breach-Daten: minimiert, Konto nur verschlüsselt + HMAC
create table public.breach_records (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  domain_id uuid not null references public.domains (id) on delete cascade,
  finding_id uuid references public.findings (id) on delete set null,
  provider text not null,
  account_hmac text not null,
  account_enc text not null,
  breach_key text not null,
  breach_title text,
  breach_date date,
  breach_added_at timestamptz,
  data_classes text[] not null default '{}',
  is_stealer_log boolean not null default false,
  is_synthetic boolean not null default false,
  first_observed_at timestamptz not null default now(),
  last_observed_at timestamptz not null default now(),
  unique (org_id, provider, account_hmac, breach_key)
);
create index breach_records_finding_idx on public.breach_records (finding_id);

-- ---------------------------------------------------------------------------
-- Maßnahmen & IT-Dienstleister
-- ---------------------------------------------------------------------------
create table public.service_provider_invites (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  email text not null check (email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  contact_name text check (char_length(contact_name) <= 120),
  company_name text check (char_length(company_name) <= 120),
  token_hash text not null unique,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  last_access_at timestamptz,
  access_count int not null default 0,
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now()
);
create index sp_invites_org_idx on public.service_provider_invites (org_id);

create table public.service_provider_shares (
  invite_id uuid not null references public.service_provider_invites (id) on delete cascade,
  finding_id uuid not null references public.findings (id) on delete cascade,
  org_id uuid not null references public.organizations (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (invite_id, finding_id)
);

create table public.actions (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  finding_id uuid not null references public.findings (id) on delete cascade,
  invite_id uuid references public.service_provider_invites (id) on delete set null,
  status text not null default 'open' check (status in ('open', 'in_progress', 'fixed_pending_verification', 'verified', 'still_open', 'cancelled')),
  note text check (char_length(note) <= 4000),
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index actions_finding_idx on public.actions (finding_id);
create index actions_org_idx on public.actions (org_id);

-- ---------------------------------------------------------------------------
-- Notfälle
-- ---------------------------------------------------------------------------
create table public.incidents (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  type text not null check (type in ('account_compromise', 'ransomware', 'phishing', 'data_exfiltration', 'suspicious_activity', 'other')),
  priority text not null check (priority in ('p1', 'p2', 'p3')),
  status text not null default 'open' check (status in ('open', 'in_progress', 'contained', 'closed')),
  title text not null check (char_length(title) between 3 and 160),
  description text check (char_length(description) <= 8000),
  reporter_name text check (char_length(reporter_name) <= 120),
  reporter_phone text check (char_length(reporter_phone) <= 40),
  assigned_contact text check (char_length(assigned_contact) <= 200),
  is_demo boolean not null default false,
  reported_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  closed_at timestamptz
);
create index incidents_org_idx on public.incidents (org_id, created_at desc);

create table public.incident_events (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  incident_id uuid not null references public.incidents (id) on delete cascade,
  type text not null check (type in ('created', 'note', 'status_changed', 'file_added', 'notification_sent', 'checklist')),
  message text check (char_length(message) <= 8000),
  data jsonb not null default '{}',
  actor_id uuid,
  actor_label text,
  created_at timestamptz not null default now()
);
create index incident_events_incident_idx on public.incident_events (incident_id, created_at);

create table public.incident_files (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  incident_id uuid not null references public.incidents (id) on delete cascade,
  storage_path text not null unique,
  file_name text not null,
  content_type text not null,
  size_bytes int not null check (size_bytes > 0 and size_bytes <= 10485760),
  sha256 text not null,
  uploaded_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Integrationen, Benachrichtigungen, Berichte, Abos, Audit
-- ---------------------------------------------------------------------------
create table public.provider_integrations (
  key text primary key,
  label text not null,
  kind text not null check (kind in ('scanner', 'intel', 'breach', 'email', 'billing')),
  status text not null default 'unknown' check (status in ('available', 'degraded', 'unavailable', 'not_configured', 'license_required', 'disabled', 'unknown')),
  status_message text,
  last_checked_at timestamptz,
  last_success_at timestamptz,
  last_error_at timestamptz,
  consecutive_failures int not null default 0,
  updated_at timestamptz not null default now()
);

create table public.notifications (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  type text not null,
  severity text not null default 'info' check (severity in ('critical', 'warning', 'info', 'success')),
  title text not null,
  body text not null,
  link text,
  dedupe_key text not null,
  read_at timestamptz,
  email_status text not null default 'pending' check (email_status in ('pending', 'sent', 'skipped', 'failed', 'suppressed')),
  email_attempts int not null default 0,
  email_sent_at timestamptz,
  email_error text,
  created_at timestamptz not null default now(),
  unique (org_id, dedupe_key)
);
create index notifications_org_idx on public.notifications (org_id, created_at desc);
create index notifications_email_idx on public.notifications (email_status, created_at) where email_status = 'pending';

create table public.reports (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  kind text not null check (kind in ('monthly', 'on_demand')),
  period_start timestamptz not null,
  period_end timestamptz not null,
  storage_path text,
  snapshot jsonb not null,
  is_demo boolean not null default false,
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now()
);
create unique index reports_monthly_unique on public.reports (org_id, period_start) where kind = 'monthly';

create table public.plans (
  key text primary key,
  name text not null,
  description text not null,
  price_cents int not null,
  currency text not null default 'eur',
  interval text not null default 'month',
  stripe_price_env text, -- Name der ENV-Variable mit der Stripe-Price-ID
  limits jsonb not null,
  features text[] not null default '{}',
  sort int not null default 0,
  active boolean not null default true
);

create table public.subscriptions (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null unique references public.organizations (id) on delete cascade,
  plan_key text not null references public.plans (key),
  status text not null check (status in ('trialing', 'active', 'past_due', 'canceled', 'unpaid', 'incomplete', 'incomplete_expired', 'paused')),
  stripe_customer_id text unique,
  stripe_subscription_id text unique,
  current_period_end timestamptz,
  cancel_at_period_end boolean not null default false,
  trial_ends_at timestamptz,
  updated_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create table public.stripe_events (
  id text primary key,
  type text not null,
  received_at timestamptz not null default now()
);

create table public.audit_logs (
  id bigint generated always as identity primary key,
  org_id uuid references public.organizations (id) on delete set null,
  actor_type text not null check (actor_type in ('user', 'system', 'partner', 'admin', 'stripe', 'public')),
  actor_id uuid,
  action text not null,
  target_type text,
  target_id text,
  ip_hash text,
  data jsonb not null default '{}',
  created_at timestamptz not null default now()
);
create index audit_logs_org_idx on public.audit_logs (org_id, created_at desc);

-- Öffentlicher Kurzcheck (Landingpage)
create table public.public_checks (
  id uuid primary key default gen_random_uuid(),
  hostname text not null,
  status text not null default 'queued' check (status in ('queued', 'running', 'done', 'failed')),
  job_id uuid references public.scan_jobs (id) on delete set null,
  ip_hash text not null,
  result jsonb,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '7 days'
);
create index public_checks_ip_idx on public.public_checks (ip_hash, created_at desc);

create table public.leads (
  id uuid primary key default gen_random_uuid(),
  email text not null check (email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  company text,
  hostname text,
  public_check_id uuid references public.public_checks (id) on delete set null,
  consent_text text not null,
  consent_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

-- Ratenbegrenzung (funktioniert ohne Redis, auch auf Serverless)
create table public.rate_limits (
  key text not null,
  window_start timestamptz not null,
  count int not null default 0,
  primary key (key, window_start)
);

-- CISA Known Exploited Vulnerabilities (öffentlicher Katalog, für deterministische Priorisierung)
create table public.cve_kev (
  cve_id text primary key,
  vendor text,
  product text,
  name text,
  date_added date,
  known_ransomware boolean not null default false
);

-- ---------------------------------------------------------------------------
-- Audit-Log ist append-only
-- ---------------------------------------------------------------------------
create or replace function public.prevent_mutation() returns trigger language plpgsql as $$
begin
  raise exception 'audit_logs is append-only';
end $$;
create trigger audit_logs_no_update before update or delete on public.audit_logs
  for each row execute function public.prevent_mutation();

-- updated_at
create or replace function public.touch_updated_at() returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;
create trigger t_org_updated before update on public.organizations for each row execute function public.touch_updated_at();
create trigger t_findings_updated before update on public.findings for each row execute function public.touch_updated_at();
create trigger t_actions_updated before update on public.actions for each row execute function public.touch_updated_at();
create trigger t_incidents_updated before update on public.incidents for each row execute function public.touch_updated_at();
create trigger t_profiles_updated before update on public.profiles for each row execute function public.touch_updated_at();

-- ---------------------------------------------------------------------------
-- Demo-Trennung: Demo-Daten nur in Demo-Mandanten, echte Daten nie in Demo-Mandanten
-- ---------------------------------------------------------------------------
create or replace function public.enforce_demo_separation() returns trigger
language plpgsql security definer set search_path = '' as $$
declare v_is_demo boolean;
begin
  select is_demo into v_is_demo from public.organizations where id = new.org_id;
  if v_is_demo is null then
    raise exception 'unknown organization';
  end if;
  if new.is_demo is distinct from v_is_demo then
    raise exception 'demo separation violated on %', tg_table_name;
  end if;
  return new;
end $$;
create trigger demo_sep_domains before insert or update on public.domains for each row execute function public.enforce_demo_separation();
create trigger demo_sep_assets before insert or update on public.assets for each row execute function public.enforce_demo_separation();
create trigger demo_sep_findings before insert or update on public.findings for each row execute function public.enforce_demo_separation();
create trigger demo_sep_incidents before insert or update on public.incidents for each row execute function public.enforce_demo_separation();
create trigger demo_sep_reports before insert or update on public.reports for each row execute function public.enforce_demo_separation();

-- Das is_demo-Flag einer Organisation ist unveränderlich
create or replace function public.org_demo_immutable() returns trigger language plpgsql as $$
begin
  if new.is_demo is distinct from old.is_demo then
    raise exception 'organizations.is_demo is immutable';
  end if;
  return new;
end $$;
create trigger org_demo_immutable before update on public.organizations for each row execute function public.org_demo_immutable();

-- Synthetische Breach-Daten nur in Demo-Mandanten
create or replace function public.enforce_synthetic_breach() returns trigger
language plpgsql security definer set search_path = '' as $$
declare v_is_demo boolean;
begin
  select is_demo into v_is_demo from public.organizations where id = new.org_id;
  if new.is_synthetic and not v_is_demo then
    raise exception 'synthetic breach data not allowed in customer organizations';
  end if;
  return new;
end $$;
create trigger breach_synthetic_guard before insert or update on public.breach_records for each row execute function public.enforce_synthetic_breach();

-- Neues Auth-Konto -> Profil
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, full_name) values (new.id, left(coalesce(new.raw_user_meta_data ->> 'full_name', ''), 120))
  on conflict (id) do nothing;
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();
