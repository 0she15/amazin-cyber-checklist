-- 004_proposals.sql
-- Proposal history for the amazin-cyber-proposals app (migrated off localStorage).
-- (Named 004, not 003, because 003_leads_crm_fields.sql already exists.)

create table if not exists public.proposals (
  id            uuid primary key default gen_random_uuid(),
  lead_id       uuid references public.leads(id),
  client_name   text,
  company       text,
  package       text,
  proposal_text text,
  operator_id   uuid references auth.users(id),
  created_at    timestamptz default now()
);

-- RLS: operator owns their rows (operator_id = auth.uid()) for all operations.
alter table public.proposals enable row level security;

drop policy if exists "proposals_select_own" on public.proposals;
create policy "proposals_select_own" on public.proposals
  for select to authenticated
  using (operator_id = auth.uid());

drop policy if exists "proposals_insert_own" on public.proposals;
create policy "proposals_insert_own" on public.proposals
  for insert to authenticated
  with check (operator_id = auth.uid());

drop policy if exists "proposals_update_own" on public.proposals;
create policy "proposals_update_own" on public.proposals
  for update to authenticated
  using (operator_id = auth.uid())
  with check (operator_id = auth.uid());

drop policy if exists "proposals_delete_own" on public.proposals;
create policy "proposals_delete_own" on public.proposals
  for delete to authenticated
  using (operator_id = auth.uid());
