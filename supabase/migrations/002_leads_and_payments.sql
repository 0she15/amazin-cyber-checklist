-- 002_leads_and_payments.sql
-- Adds leads + payments tables, links reviews to leads, and applies RLS.
-- Ownership: leads.operator_id = auth.uid(); payments scoped via lead ownership.

-- ============================================================
-- Table: leads
-- ============================================================
create table if not exists public.leads (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  company     text,
  email       text not null,
  phone       text,
  package     text,
  source      text,
  message     text,
  status      text default 'new',
  created_at  timestamptz default now(),
  updated_at  timestamptz default now(),
  operator_id uuid references auth.users(id)
);

-- ============================================================
-- Table: payments
-- ============================================================
create table if not exists public.payments (
  id                uuid primary key default gen_random_uuid(),
  lead_id           uuid references public.leads(id),
  amount            numeric,
  stripe_payment_id text,
  status            text default 'pending',
  package           text,
  created_at        timestamptz default now()
);

-- ============================================================
-- Alter: reviews -> add nullable lead_id FK
-- ============================================================
alter table public.reviews
  add column if not exists lead_id uuid references public.leads(id);

-- ============================================================
-- Row Level Security
-- ============================================================
alter table public.leads    enable row level security;
alter table public.payments enable row level security;

-- ---------- leads policies (operator owns the row) ----------
drop policy if exists "leads_select_own" on public.leads;
create policy "leads_select_own"
  on public.leads for select
  to authenticated
  using (operator_id = auth.uid());

drop policy if exists "leads_insert_own" on public.leads;
create policy "leads_insert_own"
  on public.leads for insert
  to authenticated
  with check (operator_id = auth.uid());

drop policy if exists "leads_update_own" on public.leads;
create policy "leads_update_own"
  on public.leads for update
  to authenticated
  using (operator_id = auth.uid())
  with check (operator_id = auth.uid());

-- ---------- payments policies (scoped through lead ownership) ----------
drop policy if exists "payments_select_via_lead" on public.payments;
create policy "payments_select_via_lead"
  on public.payments for select
  to authenticated
  using (
    exists (
      select 1 from public.leads l
      where l.id = payments.lead_id
        and l.operator_id = auth.uid()
    )
  );

drop policy if exists "payments_insert_via_lead" on public.payments;
create policy "payments_insert_via_lead"
  on public.payments for insert
  to authenticated
  with check (
    exists (
      select 1 from public.leads l
      where l.id = payments.lead_id
        and l.operator_id = auth.uid()
    )
  );

drop policy if exists "payments_update_via_lead" on public.payments;
create policy "payments_update_via_lead"
  on public.payments for update
  to authenticated
  using (
    exists (
      select 1 from public.leads l
      where l.id = payments.lead_id
        and l.operator_id = auth.uid()
    )
  )
  with check (
    exists (
      select 1 from public.leads l
      where l.id = payments.lead_id
        and l.operator_id = auth.uid()
    )
  );
