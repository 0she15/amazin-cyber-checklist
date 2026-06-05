# Supabase migrations — follow-ups & conventions

Tracking items surfaced while adding `002_leads_and_payments.sql`.

## Ownership column convention (decision)

**Going forward, all new tables use `operator_id` as the owner column** (referencing
`auth.users(id)`), with RLS scoped to `operator_id = auth.uid()`. Do **not** introduce
`user_id` on new tables.

- `002_leads_and_payments.sql` follows this: `leads.operator_id`, and `payments` is
  scoped through lead ownership.
- **Known inconsistency:** the existing `001_initial_schema.sql` tables (`clients`,
  `reviews`, `audit_events`) use `user_id`. These are intentionally left as-is for now.
  If we want full consistency later, that's a separate, deliberate migration
  (rename `user_id` -> `operator_id` + update every dependent RLS policy).

## `001_initial_schema.sql` does not fully reproduce the live database

A `pg_dump` of the live project (`objsgueiusdhyllcteoq`) shows two objects that
`001_initial_schema.sql` does not create, so a from-scratch `supabase db reset` will
**not** perfectly mirror production:

1. **`pg_net` extension** — present in the live DB, absent from `001`.
2. **`on_auth_user_created` trigger on `auth.users`** — fires `public.handle_new_user()`
   to seed `public.profiles`; present in the live DB, absent from `001`.

### Suggested fix (separate PR)
Add to `001_initial_schema.sql` (or a new `003_*` migration):

```sql
create extension if not exists pg_net;

-- handle_new_user() must exist before this trigger
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();
```

## Migration-history note

The live DB's `supabase_migrations.schema_migrations` table is reconciled to exactly
`{001, 002}`, matching the repo. `supabase migration list --linked` shows both aligned
Local ↔ Remote with no drift. Earlier exploratory timestamp-named entries were removed.
