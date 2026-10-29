-- =====================================================================
-- DAILY STUDY GOAL — the "dashboard as tracker" ring (2026-10-28)
-- ---------------------------------------------------------------------
-- One column on the existing progress table. Run in the Supabase SQL
-- editor (single STAGE, same pattern as supabase-admin.sql).
--
-- RLS: the column rides on progress's existing policies; nothing new
-- here. Client behavior if this is NOT run before deploy: the app
-- degrades gracefully (same path as the ce_* columns) — the ring
-- renders from today_seconds against the 30m default and the choice
-- simply isn't persisted.
-- =====================================================================

alter table public.progress
  add column if not exists daily_goal_minutes integer;

comment on column public.progress.daily_goal_minutes is
  'Daily study goal the learner picks (minutes). NULL = client default 30.';