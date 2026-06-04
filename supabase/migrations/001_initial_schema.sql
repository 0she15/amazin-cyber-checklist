-- Phase 2A: authenticated Supabase persistence with row-level security.
-- Apply this migration in your Supabase project SQL editor or migration pipeline.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  full_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.clients (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade default auth.uid(),
  name text not null,
  contact_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.reviews (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade default auth.uid(),
  client_id uuid not null references public.clients(id) on delete cascade,
  package text,
  license_type text,
  user_count text,
  reviewer_name text not null,
  review_date date not null default current_date,
  scope text not null,
  notes text,
  secure_score_notes text,
  duration_ms integer not null default 0,
  completed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.review_items (
  id uuid primary key default gen_random_uuid(),
  review_id uuid not null references public.reviews(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade default auth.uid(),
  check_id text not null,
  result text check (result in ('pass', 'fail', 'na') or result is null),
  notes text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (review_id, check_id)
);

create table if not exists public.generated_reports (
  id uuid primary key default gen_random_uuid(),
  review_id uuid not null references public.reviews(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade default auth.uid(),
  report jsonb not null,
  score jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.audit_events (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete set null default auth.uid(),
  review_id uuid references public.reviews(id) on delete set null,
  event_type text not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create or replace function public.touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, full_name)
  values (new.id, new.email, coalesce(new.raw_user_meta_data ->> 'full_name', ''))
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

drop trigger if exists touch_profiles_updated_at on public.profiles;
create trigger touch_profiles_updated_at before update on public.profiles
for each row execute function public.touch_updated_at();

drop trigger if exists touch_clients_updated_at on public.clients;
create trigger touch_clients_updated_at before update on public.clients
for each row execute function public.touch_updated_at();

drop trigger if exists touch_reviews_updated_at on public.reviews;
create trigger touch_reviews_updated_at before update on public.reviews
for each row execute function public.touch_updated_at();

drop trigger if exists touch_review_items_updated_at on public.review_items;
create trigger touch_review_items_updated_at before update on public.review_items
for each row execute function public.touch_updated_at();

alter table public.profiles enable row level security;
alter table public.clients enable row level security;
alter table public.reviews enable row level security;
alter table public.review_items enable row level security;
alter table public.generated_reports enable row level security;
alter table public.audit_events enable row level security;

create policy "profiles_select_own" on public.profiles
  for select to authenticated using (id = auth.uid());
create policy "profiles_update_own" on public.profiles
  for update to authenticated using (id = auth.uid()) with check (id = auth.uid());
create policy "profiles_insert_own" on public.profiles
  for insert to authenticated with check (id = auth.uid());

create policy "clients_select_own" on public.clients
  for select to authenticated using (user_id = auth.uid());
create policy "clients_insert_own" on public.clients
  for insert to authenticated with check (user_id = auth.uid());
create policy "clients_update_own" on public.clients
  for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "clients_delete_own" on public.clients
  for delete to authenticated using (user_id = auth.uid());

create policy "reviews_select_own" on public.reviews
  for select to authenticated using (user_id = auth.uid());
create policy "reviews_insert_own" on public.reviews
  for insert to authenticated with check (
    user_id = auth.uid()
    and exists (select 1 from public.clients c where c.id = client_id and c.user_id = auth.uid())
  );
create policy "reviews_update_own" on public.reviews
  for update to authenticated using (user_id = auth.uid()) with check (
    user_id = auth.uid()
    and exists (select 1 from public.clients c where c.id = client_id and c.user_id = auth.uid())
  );
create policy "reviews_delete_own" on public.reviews
  for delete to authenticated using (user_id = auth.uid());

create policy "review_items_select_own" on public.review_items
  for select to authenticated using (user_id = auth.uid());
create policy "review_items_insert_own" on public.review_items
  for insert to authenticated with check (
    user_id = auth.uid()
    and exists (select 1 from public.reviews r where r.id = review_id and r.user_id = auth.uid())
  );
create policy "review_items_update_own" on public.review_items
  for update to authenticated using (user_id = auth.uid()) with check (
    user_id = auth.uid()
    and exists (select 1 from public.reviews r where r.id = review_id and r.user_id = auth.uid())
  );
create policy "review_items_delete_own" on public.review_items
  for delete to authenticated using (user_id = auth.uid());

create policy "generated_reports_select_own" on public.generated_reports
  for select to authenticated using (user_id = auth.uid());
create policy "generated_reports_insert_own" on public.generated_reports
  for insert to authenticated with check (
    user_id = auth.uid()
    and exists (select 1 from public.reviews r where r.id = review_id and r.user_id = auth.uid())
  );
create policy "generated_reports_delete_own" on public.generated_reports
  for delete to authenticated using (user_id = auth.uid());

create policy "audit_events_select_own" on public.audit_events
  for select to authenticated using (user_id = auth.uid());
create policy "audit_events_insert_own" on public.audit_events
  for insert to authenticated with check (
    user_id = auth.uid()
    and (
      review_id is null
      or exists (select 1 from public.reviews r where r.id = review_id and r.user_id = auth.uid())
    )
  );

create index if not exists clients_user_id_created_at_idx on public.clients(user_id, created_at desc);
create index if not exists reviews_user_id_created_at_idx on public.reviews(user_id, created_at desc);
create index if not exists reviews_client_id_idx on public.reviews(client_id);
create index if not exists review_items_review_id_idx on public.review_items(review_id);
create index if not exists generated_reports_review_id_created_at_idx on public.generated_reports(review_id, created_at desc);
