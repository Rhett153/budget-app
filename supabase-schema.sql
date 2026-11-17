-- Budget App cloud sync stores only the AES-GCM encrypted local vault record.
-- Apply this in the Supabase SQL Editor after creating a project.

create table if not exists public.encrypted_vaults (
  user_id uuid primary key references auth.users (id) on delete cascade,
  record jsonb not null,
  revision bigint not null default 1 check (revision > 0),
  updated_at timestamptz not null default now()
);

alter table public.encrypted_vaults enable row level security;

drop policy if exists "Read own encrypted vault" on public.encrypted_vaults;
create policy "Read own encrypted vault"
  on public.encrypted_vaults
  for select
  to authenticated
  using ((select auth.uid()) = user_id);

revoke all on table public.encrypted_vaults from anon, authenticated;
grant select on table public.encrypted_vaults to authenticated;

create or replace function public.save_my_encrypted_vault(
  p_expected_revision bigint,
  p_record jsonb
)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  current_user_id uuid := auth.uid();
  saved_revision bigint;
begin
  if current_user_id is null then
    raise exception using errcode = '42501', message = 'Authentication required.';
  end if;

  if p_record is null or p_expected_revision is null or p_expected_revision < 0 then
    raise exception using errcode = '22023', message = 'Invalid vault record or revision.';
  end if;

  if p_expected_revision = 0 then
    insert into public.encrypted_vaults (user_id, record, revision, updated_at)
    values (current_user_id, p_record, 1, now())
    on conflict (user_id) do nothing
    returning revision into saved_revision;
  else
    update public.encrypted_vaults as vault
       set record = p_record,
           revision = vault.revision + 1,
           updated_at = now()
     where vault.user_id = current_user_id
       and vault.revision = p_expected_revision
    returning revision into saved_revision;
  end if;

  if saved_revision is null then
    raise exception using errcode = '40001', message = 'VAULT_REVISION_CONFLICT';
  end if;

  return saved_revision;
end;
$$;

revoke all on function public.save_my_encrypted_vault(bigint, jsonb) from public, anon;
grant execute on function public.save_my_encrypted_vault(bigint, jsonb) to authenticated;
