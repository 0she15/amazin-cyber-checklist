-- 003_leads_crm_fields.sql
-- CRM-managed fields on leads so the pipeline UI can persist operator notes
-- and follow-up dates alongside inbound website submissions.

alter table public.leads
  add column if not exists notes text,
  add column if not exists next_action_date date;
