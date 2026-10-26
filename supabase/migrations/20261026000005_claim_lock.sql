-- Race-freie Job-Übernahme: pro Organisation transaktionaler Advisory-Lock,
-- damit parallele Worker nie zwei Jobs derselben Organisation gleichzeitig starten.
create or replace function public.claim_scan_job(p_worker text, p_kinds text[])
returns setof public.scan_jobs language plpgsql security definer set search_path = '' as $$
declare
  c record;
  r public.scan_jobs;
begin
  for c in
    select j.id, j.org_id from public.scan_jobs j
     where j.status = 'queued' and j.run_after <= now() and j.kind = any (p_kinds) and not j.cancel_requested
       and (j.org_id is null or exists (
             select 1 from public.organizations o where o.id = j.org_id and not o.is_demo and o.deleted_at is null))
     order by j.priority desc, j.created_at
     for update of j skip locked
     limit 25
  loop
    if c.org_id is not null then
      if not pg_try_advisory_xact_lock(hashtextextended('scan_org:' || c.org_id::text, 0)) then
        continue;
      end if;
      if exists (select 1 from public.scan_jobs x where x.org_id = c.org_id and x.status = 'running') then
        continue;
      end if;
    end if;
    update public.scan_jobs
       set status = 'running', locked_by = p_worker, locked_at = now(), heartbeat_at = now(),
           attempts = attempts + 1, started_at = coalesce(started_at, now())
     where id = c.id
     returning * into r;
    return next r;
    return;
  end loop;
  return;
end $$;

revoke execute on function public.claim_scan_job(text, text[]) from public, anon, authenticated;
grant execute on function public.claim_scan_job(text, text[]) to service_role;
