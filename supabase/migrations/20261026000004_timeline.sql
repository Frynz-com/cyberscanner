-- Einheitliche Sicherheits-Timeline (Modul E): jedes Ereignis mit Nutzen für den Kunden
create table public.timeline_events (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  type text not null check (type in (
    'scan_completed', 'scan_failed', 'asset_discovered', 'finding_detected', 'finding_reappeared', 'breach_detected',
    'shared_with_partner', 'partner_update', 'status_changed', 'reverify_passed', 'reverify_failed', 'report_created',
    'incident_reported', 'domain_verified', 'domain_added', 'authorization_granted', 'monitoring_changed')),
  severity text not null default 'info' check (severity in ('critical', 'high', 'medium', 'low', 'info', 'success')),
  title text not null,
  body text,
  link text,
  finding_id uuid references public.findings (id) on delete set null,
  domain_id uuid references public.domains (id) on delete set null,
  data jsonb not null default '{}',
  is_demo boolean not null default false,
  created_at timestamptz not null default now()
);
create index timeline_events_org_idx on public.timeline_events (org_id, created_at desc);
alter table public.timeline_events enable row level security;
alter table public.timeline_events force row level security;
grant select on public.timeline_events to authenticated;
create policy timeline_member_read on public.timeline_events for select to authenticated using (public.is_org_member(org_id));
create trigger demo_sep_timeline before insert or update on public.timeline_events for each row execute function public.enforce_demo_separation();

-- Zähler für Monitoring-Abdeckung pro Domain (letzter erfolgreicher Lauf je Adapter)
create or replace view public.domain_coverage with (security_invoker = true) as
select distinct on (r.domain_id, r.adapter)
  r.org_id, r.domain_id, r.adapter, r.status, r.message, r.finished_at, r.checks, r.targets
from public.scan_results r
where r.domain_id is not null
order by r.domain_id, r.adapter, r.finished_at desc;
grant select on public.domain_coverage to authenticated;
