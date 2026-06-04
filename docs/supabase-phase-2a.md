# Supabase Phase 2A setup

1. Create a Supabase project.
2. Apply `supabase/migrations/001_initial_schema.sql` in the SQL editor or migration pipeline.
3. Configure auth email/password settings in Supabase Auth.
4. Add these deployment variables in local development and Vercel:
   - `NEXT_PUBLIC_SUPABASE_URL`
   - `NEXT_PUBLIC_SUPABASE_ANON_KEY`
   - `AMAZIN_CYBER_REPORT`
5. Do not add a Supabase service-role key to browser code or `NEXT_PUBLIC_*` variables.

The migration enables RLS on all app tables. Policies scope rows to `auth.uid()` so authenticated users can only access their own clients, reviews, checklist items, reports, and audit events.

## Manual verification checklist

- With Supabase env vars missing, the app should show the configuration-required screen and no review data.
- Sign up or sign in with email/password.
- Create a client review and confirm the row appears in `clients` and `reviews` with the authenticated user's `user_id`.
- Mark checklist items pass/fail/N/A and add notes; confirm `review_items` rows are saved for that review.
- Refresh the browser and confirm the same signed-in user can reload review history from Supabase.
- Sign out and confirm the review list disappears and no client review data remains visible in the UI.
- Sign in as a different user in the same browser and confirm the previous user's reviews are not visible.
- Complete at least 60% / 20 recognized checks, generate a report, and confirm a row is saved in `generated_reports` with the authenticated user's `user_id`.
- Reopen the report modal for that review and confirm the latest generated report loads from `generated_reports`.
- Call `/api/generate-report` without a bearer token or with another user's review ID; it should fail.
