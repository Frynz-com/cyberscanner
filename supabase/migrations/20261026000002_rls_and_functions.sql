-- Row Level Security: konsequent für alle Tabellen aktiviert.
-- Keine Policy = kein Zugriff für anon/authenticated. Service Role umgeht RLS (nur serverseitig).

do $$
declare t text;
begin
  foreach t in array array[
    'profiles', 'roles', 'organizations', 'memberships', 'platform_admins', 'domains', 'verification_challenges',
    'scan_authorizations', 'assets', 'scan_jobs', 'scan_results', 'findings', 'finding_events', 'breach_records',
    'service_provider_invites', 'service_provider_shares', 'actions', 'incidents', 'incident_events', 'incident_files',
    'provider_integrations', 'notifications', 'reports', 'plans', 'subscriptions', 'stripe_events', 'audit_logs',
    'public_checks', 'leads', 'rate_limits', 'cve_kev']
  loop
    execute format('alter table public.%I enable row level security', t);
    execute format('alter table public.%I force row level security', t);
  end loop;
end $$;

-- Anonyme Rolle erhält auf Tabellen grundsätzlich nichts.
revoke all on all tables in schema public from anon;
-- authenticated: nur SELECT (gefiltert durch RLS) und Update des eigenen Profils
revoke insert, update, delete, truncate on all tables in schema public from authenticated;
grant select on all tables in schema public to authenticated;
grant update (full_name) on public.profiles to authenticated;

-- Sensible Tabellen, die Kunden nie direkt lesen dürfen
revoke select on public.verification_challenges, public.stripe_events, public.rate_limits, public.leads,
  public.public_checks, public.platform_admins, public.service_provider_invites, public.breach_records
  from authenticated;
-- Einladungen ohne token_hash lesbar machen (Spaltenrechte)
grant select (id, org_id, email, contact_name, company_name, expires_at, revoked_at, last_access_at, access_count, created_at)
  on public.service_provider_invites to authenticated;
-- Verifizierungs-Challenges: Token ist kein Geheimnis gegenüber Mitgliedern, aber nur relevante Spalten
grant select (id, org_id, domain_id, record_name, token, created_at, expires_at, attempts, last_checked_at, last_result, consumed_at)
  on public.verification_challenges to authenticated;
-- Breach-Records: verschlüsselte Kontodaten nie an Clients, nur Metadaten
grant select (id, org_id, domain_id, finding_id, provider, breach_key, breach_title, breach_date, breach_added_at,
  data_classes, is_stealer_log, is_synthetic, first_observed_at, last_observed_at)
  on public.breach_records to authenticated;

-- Profile
create policy profiles_self_select on public.profiles for select to authenticated
  using (id = (select auth.uid()) or exists (
    select 1 from public.memberships a join public.memberships b on a.org_id = b.org_id
    where a.user_id = (select auth.uid()) and b.user_id = profiles.id));
create policy profiles_self_update on public.profiles for update to authenticated
  using (id = (select auth.uid())) with check (id = (select auth.uid()));

-- Öffentliche Referenzdaten
create policy roles_read on public.roles for select to authenticated using (true);
create policy plans_read on public.plans for select to authenticated using (active);
create policy providers_read on public.provider_integrations for select to authenticated using (true);
create policy kev_read on public.cve_kev for select to authenticated using (true);

-- Organisationen & Mitgliedschaften
create policy orgs_member_read on public.organizations for select to authenticated
  using (deleted_at is null and public.is_org_member(id));
create policy memberships_read on public.memberships for select to authenticated
  using (public.is_org_member(org_id));

-- Generische Mitglieder-Lese-Policies für mandantenbezogene Tabellen
do $$
declare t text;
begin
  foreach t in array array[
    'domains', 'verification_challenges', 'scan_authorizations', 'assets', 'scan_jobs', 'scan_results', 'findings',
    'finding_events', 'breach_records', 'service_provider_invites', 'service_provider_shares', 'actions', 'incidents',
    'incident_events', 'incident_files', 'notifications', 'reports', 'subscriptions']
  loop
    execute format(
      'create policy %I on public.%I for select to authenticated using (public.is_org_member(org_id))',
      t || '_member_read', t);
  end loop;
end $$;

-- Audit-Logs: nur Admins/Inhaber der Organisation
create policy audit_admin_read on public.audit_logs for select to authenticated
  using (org_id is not null and public.org_role_rank(org_id) >= 80);

-- Plattform-Admins: lesen nur ihren eigenen Eintrag (Admin-UI nutzt serverseitige Service Role)
create policy platform_admin_self on public.platform_admins for select to authenticated
  using (user_id = (select auth.uid()));
grant select on public.platform_admins to authenticated;

-- ---------------------------------------------------------------------------
-- Funktionen für Worker/Server (nur service_role)
-- ---------------------------------------------------------------------------

-- Atomare Job-Übernahme mit SKIP LOCKED; max. 1 laufender Job pro Organisation;
-- Demo-/gelöschte Organisationen werden nie gescannt.
create or replace function public.claim_scan_job(p_worker text, p_kinds text[])
returns setof public.scan_jobs language plpgsql security definer set search_path = '' as $$
begin
  return query
  update public.scan_jobs j
     set status = 'running', locked_by = p_worker, locked_at = now(), heartbeat_at = now(),
         attempts = j.attempts + 1, started_at = coalesce(j.started_at, now())
   where j.id = (
     select c.id from public.scan_jobs c
      where c.status = 'queued' and c.run_after <= now() and c.kind = any (p_kinds) and not c.cancel_requested
        and (c.org_id is null or exists (
              select 1 from public.organizations o
               where o.id = c.org_id and not o.is_demo and o.deleted_at is null))
        and (c.org_id is null or not exists (
              select 1 from public.scan_jobs r where r.org_id = c.org_id and r.status = 'running'))
      order by c.priority desc, c.created_at
      for update skip locked
      limit 1)
  returning j.*;
end $$;

-- Hängende Jobs wiederaufnehmen (Worker-Absturz)
create or replace function public.requeue_stale_jobs(p_stale_seconds int default 300)
returns int language plpgsql security definer set search_path = '' as $$
declare n int;
begin
  with stale as (
    select id, attempts, max_attempts from public.scan_jobs
     where status = 'running' and heartbeat_at < now() - make_interval(secs => p_stale_seconds)
     for update skip locked)
  update public.scan_jobs j
     set status = case when s.attempts >= s.max_attempts then 'failed'::public.job_status else 'queued'::public.job_status end,
         error = 'Worker-Heartbeat abgelaufen',
         locked_by = null, locked_at = null,
         run_after = now() + make_interval(secs => 30 * power(2, s.attempts)::int),
         finished_at = case when s.attempts >= s.max_attempts then now() else null end
    from stale s where j.id = s.id;
  get diagnostics n = row_count;
  return n;
end $$;

-- Ratenbegrenzung: true = erlaubt
create or replace function public.rate_limit_hit(p_key text, p_window_seconds int, p_max int)
returns boolean language plpgsql security definer set search_path = '' as $$
declare v_window timestamptz := to_timestamp(floor(extract(epoch from now()) / p_window_seconds) * p_window_seconds);
        v_count int;
begin
  insert into public.rate_limits (key, window_start, count) values (p_key, v_window, 1)
  on conflict (key, window_start) do update set count = public.rate_limits.count + 1
  returning count into v_count;
  return v_count <= p_max;
end $$;

-- Organisation + Inhaber-Mitgliedschaft atomar anlegen (vom Server nach Auth-Prüfung aufgerufen)
create or replace function public.create_organization(p_user uuid, p_name text, p_industry text, p_employee_range text, p_contact_email text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare v_org uuid;
begin
  insert into public.organizations (name, industry, employee_range, contact_email, created_by, onboarding_step)
  values (p_name, nullif(p_industry, ''), nullif(p_employee_range, ''), nullif(p_contact_email, ''), p_user, 3)
  returning id into v_org;
  insert into public.memberships (org_id, user_id, role) values (v_org, p_user, 'owner');
  insert into public.subscriptions (org_id, plan_key, status, trial_ends_at)
  values (v_org, 'trial', 'trialing', now() + interval '14 days');
  return v_org;
end $$;

do $$
declare f text;
begin
  foreach f in array array[
    'claim_scan_job(text, text[])', 'requeue_stale_jobs(int)', 'rate_limit_hit(text, int, int)',
    'create_organization(uuid, text, text, text, text)', 'enforce_demo_separation()', 'enforce_synthetic_breach()',
    'handle_new_user()']
  loop
    execute format('revoke execute on function public.%s from public, anon, authenticated', f);
    execute format('grant execute on function public.%s to service_role', f);
  end loop;
end $$;

-- RLS-Helfer dürfen von authenticated ausgeführt werden (liefern nur Infos über den Aufrufer)
revoke execute on function public.is_org_member(uuid) from public, anon;
revoke execute on function public.org_role_rank(uuid) from public, anon;
revoke execute on function public.is_platform_admin() from public, anon;

-- Standardrechte für künftig angelegte Tabellen: kein Schreibrecht für Clients
alter default privileges in schema public revoke insert, update, delete, truncate on tables from authenticated, anon;
alter default privileges in schema public revoke select on tables from anon;
