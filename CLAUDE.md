# Project conventions

## Supabase / database
- **Owner column on new tables is `operator_id`** (uuid, references `auth.users(id)`).
  Do NOT use `user_id` on new tables. RLS scopes to `operator_id = auth.uid()`; for
  child tables, scope through the parent's ownership.
- Migrations use the `NNN_name.sql` convention (`001_`, `002_`, …). Keep local files
  aligned with the remote `supabase_migrations.schema_migrations` history.
- See `docs/supabase-followups.md` for known gaps in `001_initial_schema.sql`.
