-- Audit-Log bleibt append-only; einzige erlaubte Änderung: Entkopplung von einer
-- gelöschten Organisation (ON DELETE SET NULL), damit das Löschkonzept funktioniert.
create or replace function public.prevent_mutation() returns trigger language plpgsql as $$
begin
  if tg_op = 'UPDATE'
     and old.org_id is not null and new.org_id is null
     and (to_jsonb(new) - 'org_id') = (to_jsonb(old) - 'org_id') then
    return new;
  end if;
  raise exception 'audit_logs is append-only';
end $$;
