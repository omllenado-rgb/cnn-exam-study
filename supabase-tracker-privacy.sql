-- =====================================================================
-- STAGE 7 — LOCK practice-test history behind session tokens (2026-10-28)
-- ---------------------------------------------------------------------
-- FINDING THIS CLOSES. `test_results` had NO row-level security at all: with
-- only the publishable key, anyone could page every learner's practice-exam
-- history (name, score, per-objective breakdown) and could also INSERT fake
-- results for any user. The app reads and writes only its OWN learner's rows,
-- and admin.html reads everything — both now carry a token the policy can
-- verify.
--
-- MECHANISM. There is no Supabase auth session in this app (login is the
-- custom login_check RPC), so RLS policies are gated on a custom request
-- header token issued at login. This reuses the admin machinery's exact
-- pattern (supabase-admin.sql): a stateless HMAC token, signed with the
-- shared token_key (admin_config 'token_key'). Layout:
--   learner token  'l1:<name>:<expires>:<rand>.<hmac>'  TTL 7 days
--   admin token    'v1.<epoch>.<admin>.<exp>.<rand>.<hmac>'  (existing)
-- Learner names may contain '.' (NAME_RE allows "Mrs. Smith"), so the
-- VERIFIER takes the hmac after the LAST '.' and the payload is
-- ':'-separated (':' is not an allowed name character).
--
-- DEPLOY ORDER (same convention as STAGE 1->3):
--   1. run this file
--   2. deploy the new index.html + admin.html (GitHub Pages, ~2 min, 10-min
--      cache floor)
--   Pages still holding an old page during the overlap window: login still
--   works (login_check is additive), and the Blueprint tracker + test-result
--   save just show their "could not load" degrade until the new page loads.
--   The test-result save is already non-blocking by design.
--
-- ROLL BACK = re-run the two drop-policy statements below at the bottom.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ------------------------------------------------- learner token issuer ----
create or replace function public._learner_issue_token(p_user text, p_ttl_minutes integer default 10080)
returns jsonb
language plpgsql security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_exp     bigint;
  v_payload text;
begin
  if p_user is null or btrim(p_user) = '' then
    return jsonb_build_object('status', 'error');
  end if;
  v_exp     := extract(epoch from now())::bigint
               + greatest(1, least(coalesce(p_ttl_minutes, 10080), 20160)) * 60;
  -- ':' separators: learner names may contain '.' (see header comment)
  v_payload := 'l1:' || p_user || ':' || v_exp
               || ':' || encode(gen_random_bytes(8), 'hex');
  return jsonb_build_object(
    'status',     'ok',
    'token',      v_payload || '.' || encode(hmac(v_payload, public._admin_signing_key(), 'sha256'), 'hex'),
    'expires_at', to_timestamp(v_exp)
  );
end; $$;

-- Verify a learner token: returns the learner name, or null. STABLE, so RLS
-- can call it. Never granted to callers; reachable only through the policy
-- helpers below.
create or replace function public._learner_verify_token(p_token text)
returns text
language plpgsql security definer stable
set search_path = public, extensions, pg_temp
as $$
declare
  v_parts   text[];
  v_sig     text;
  v_payload text;
  p         text[];
  v_name    text;
  v_exp     bigint;
begin
  if p_token is null or length(p_token) > 400 then return null; end if;
  -- The signature is everything after the LAST '.' — the payload may itself
  -- contain '.', because the learner's name may contain '.' ("Mrs. Smith").
  -- The payload is ':'-separated; ':' is not an allowed name character.
  v_parts := string_to_array(p_token, '.');
  v_sig := v_parts[array_length(v_parts, 1)];
  v_payload := left(p_token, length(p_token) - length(v_sig) - 1);
  if v_payload = '' or v_sig is null or v_sig = '' then return null; end if;
  if encode(hmac(v_payload, public._admin_signing_key(), 'sha256'), 'hex') <> btrim(v_sig) then
    return null;
  end if;
  p := string_to_array(v_payload, ':');
  if array_length(p, 1) <> 4 or p[1] <> 'l1' or btrim(p[2]) = '' then return null; end if;
  v_name := p[2];
  begin
    v_exp := p[3]::bigint;
  exception when invalid_text_representation then return null;
  end;
  if v_exp < extract(epoch from now())::bigint then return null; end if;
  return v_name;
end; $$;

-- RLS policy helpers. PostgREST exposes all request headers as the
-- request.headers GUC; a missing/unparseable header yields a clean deny.
create or replace function public.session_row_user()
returns text
language plpgsql security definer stable
set search_path = public, extensions, pg_temp
as $$
declare
  h text;
begin
  begin
    h := coalesce(current_setting('request.headers', true), '');
    if h is null or btrim(h) = '' then return null; end if;
    return public._learner_verify_token(h::json ->> 'x-learner-token');
  exception when others then return null;
  end;
end; $$;

create or replace function public.session_admin_ok()
returns boolean
language plpgsql security definer stable
set search_path = public, extensions, pg_temp
as $$
declare
  h text;
begin
  begin
    h := coalesce(current_setting('request.headers', true), '');
    if h is null or btrim(h) = '' then return false; end if;
    return public._admin_verify_token(h::json ->> 'x-admin-token') is not null;
  exception when others then return false;
  end;
end; $$;

-- ------------------------------------------------- issue at the two doors --
-- login_check: same live STAGE-1 logic, plus a token in the ok response.
create or replace function public.login_check(p_user text, p_pass text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_name    text;
  v_csalt   text;   -- salt in the locked table
  v_chash   text;   -- hash  in the locked table
  v_psalt   text;   -- salt still in the progress row
  v_phash   text;   -- hash  still in the progress row
  v_plain   text;   -- legacy plaintext column
  v_ok      boolean := false;
  v_new     text;
  v_profile jsonb;
begin
  select p.user_name, c.pass_salt, c.pass_hash, p.pass_salt, p.pass_hash, p.password
    into v_name, v_csalt, v_chash, v_psalt, v_phash, v_plain
    from public.progress p
    left join public.credentials c on c.user_name = p.user_name
   where lower(p.user_name) = lower(btrim(coalesce(p_user, '')))
   limit 1;

  if v_name is null then
    return jsonb_build_object('status', 'no_user');
  end if;

  if v_chash is not null
     and v_chash = encode(digest(coalesce(v_csalt, '') || '::' || p_pass, 'sha256'), 'hex') then
    v_ok := true;

  elsif v_phash is not null
     and v_phash = encode(digest(coalesce(v_psalt, '') || '::' || p_pass, 'sha256'), 'hex') then
    v_ok := true;
    insert into public.credentials (user_name, pass_salt, pass_hash)
    values (v_name, coalesce(v_psalt, ''), v_phash)
    on conflict (user_name) do update
       set pass_salt = excluded.pass_salt,
           pass_hash = excluded.pass_hash,
           updated_at = now();
    update public.progress
       set pass_hash = null, pass_salt = null
     where user_name = v_name;

  elsif v_plain is not null and v_plain = p_pass then
    v_ok := true;
    v_new := encode(gen_random_bytes(16), 'hex');
    insert into public.credentials (user_name, pass_salt, pass_hash)
    values (v_name, v_new, encode(digest(v_new || '::' || p_pass, 'sha256'), 'hex'))
    on conflict (user_name) do update
       set pass_salt = excluded.pass_salt,
           pass_hash = excluded.pass_hash,
           updated_at = now();
    update public.progress set password = null where user_name = v_name;
  end if;

  if not v_ok then
    return jsonb_build_object('status', 'bad_password');
  end if;

  select to_jsonb(p) - 'pass_hash' - 'pass_salt' - 'password'
    into v_profile
    from public.progress p
   where p.user_name = v_name;

  -- THE ONE ADDITION vs STAGE 1: a learner token rides the ok response.
  return jsonb_build_object('status', 'ok', 'profile', v_profile)
         || public._learner_issue_token(v_name);
end;
$$;

-- create_account: keep the STAGE-4 logic verbatim; add the token so a
-- brand-new account is immediately authorized for its own blueprint read.
create or replace function public.create_account(p_user text, p_pass text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_name     text := lower(btrim(coalesce(p_user, '')));
  v_salt     text;
  v_existing text;
  v_rows     integer;
begin
  if v_name = '' or coalesce(p_pass, '') = '' then
    return jsonb_build_object('status', 'invalid');
  end if;

  select c.user_name into v_existing
    from public.credentials c
   where lower(c.user_name) = v_name
   limit 1;

  if v_existing is null then
    select p.user_name into v_existing
      from public.progress p
     where lower(p.user_name) = v_name
     limit 1;
  end if;

  if v_existing is not null then
    return jsonb_build_object('status', 'exists');
  end if;

  v_salt := encode(gen_random_bytes(16), 'hex');

  insert into public.credentials (user_name, pass_salt, pass_hash)
  values (v_name, v_salt, encode(digest(v_salt || '::' || p_pass, 'sha256'), 'hex'))
  on conflict (user_name) do nothing;

  get diagnostics v_rows = row_count;
  if v_rows = 0 then
    return jsonb_build_object('status', 'exists');
  end if;

  return jsonb_build_object('status', 'ok', 'user_name', v_name)
         || public._learner_issue_token(v_name);
end;
$$;

-- ------------------------------------------------------------ the policies --
alter table public.test_results enable row level security;

drop policy if exists test_results_select on public.test_results;
drop policy if exists test_results_insert on public.test_results;

-- A learner sees only rows carrying their own name (token in the request
-- header); the admin may read all rows.
create policy test_results_select on public.test_results
  for select using ( user_name = public.session_row_user() or public.session_admin_ok() );

-- Learners may write only their OWN history (the anon key could insert fake
-- results for anyone before this).
create policy test_results_insert on public.test_results
  for insert with check ( user_name = public.session_row_user() );

-- ------------------------------------------------------------ the revokes ---
-- Functions default to EXECUTE TO PUBLIC: without these, _learner_issue_token
-- would be an anon-callable token mint for ANY learner name — the exact hole
-- supabase-admin.sql STAGE 1 closes on its own issuer. (Caught live on
-- 2026-10-28 with a probe before any client deploy; closed same day.)
--
-- The two policy helpers (session_row_user / session_admin_ok) are DELIBERATELY
-- NOT revoked: RLS evaluates a policy's expressions with the calling role's
-- privileges, so the anonymous learner query needs EXECUTE on them. They deny
-- cleanly (null/false) without a valid token, so executable-by-anon is safe.
revoke all on function public._learner_issue_token(text, integer) from public, anon, authenticated;
revoke all on function public._learner_verify_token(text)          from public, anon, authenticated;

-- ------------------------------------------------------------- verification --
-- Run these after deploying (each must return exactly what the comment says):
--   select public._learner_verify_token(
--            'l1:Oliver:9999999999:fedcba.deadhex');   -- null: forged denied
--   -- with a real token t from login_check:
--   select public._learner_verify_token(t);           -- the learner name
--   -- a name containing a dot must survive round-trip:
--   --   select public._learner_verify_token( public._learner_issue_token('Mrs. Smith')->>'token' );
--   -- RLS end-to-end, anon key, no header -> [] instead of every learner:
--   --   GET {url}/rest/v1/test_results?select=user_name&limit=5

-- ------------------------------------------------------------- roll back ----
-- drop policy if exists test_results_select on public.test_results;
-- drop policy if exists test_results_insert on public.test_results;
-- alter table public.test_results disable row level security;