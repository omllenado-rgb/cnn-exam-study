-- ============================================================================
-- CNN Study App — admin authentication foundation
-- ============================================================================
-- WHY THIS FILE EXISTS
--   Two live holes in the current setup:
--
--   1. public.request_reset(text) is granted to `anon` AND returns the reset
--      code it just generated (supabase-password-reset.sql:117, :59). Anyone
--      holding the public anon key — which ships in index.html — can generate
--      a code for any learner and then call reset_password() to set a new
--      password on that account. Two requests, silent, and it grants access.
--
--   2. The admin gate is readable. admin.html:138 carries the access code as a
--      plain literal, and admin.html:161 reads the admin password verifier out
--      of app_settings, which the anon key can read.
--
-- HOW THIS FILE FIXES THEM
--   The dashboard and an attacker share one credential (the public anon key),
--   so GRANT/REVOKE cannot tell them apart. Every privileged function below
--   therefore stays reachable by anon and proves identity itself, with an
--   HMAC-signed token whose signing key lives only inside Postgres. The token
--   is the security boundary; the grant is not.
--
-- !! RUN ORDER — READ BEFORE RUNNING !!
--   STAGE 1  (below)  — additive. Safe to re-run. Run it first.
--   STAGE 2  (below)  — pick a new admin password, run once.
--   ... deploy the new admin.html ...
--   STAGE 3  (bottom) — the ONLY destructive block. Run it separately, only
--                       after the new dashboard is confirmed working.
--   Nothing here touches a single row of learner data.
-- ============================================================================


-- ============================================================================
-- STAGE 1 — additive objects and functions. Changes nothing the running app
--           does today. Idempotent: safe to run more than once.
-- ============================================================================

create extension if not exists pgcrypto with schema extensions;

-- --------------------------------------------------------------- secrets ---
-- The admin password verifier. RLS on, no policies, revoked from anon — so
-- unlike app_settings today, this is NOT readable with the public key.
create table if not exists public.admin_secrets (
  admin_name    text primary key,
  pass_hash     text not null,                  -- bcrypt, from crypt(..., gen_salt('bf'))
  is_active     boolean not null default true,
  key_epoch     integer not null default 1,     -- bump to invalidate all tokens
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  last_login_at timestamptz
);
alter table public.admin_secrets enable row level security;
revoke all on public.admin_secrets from anon, authenticated;

-- Single-row config holding the token signing key. Server-side only.
create table if not exists public.admin_config (
  key        text primary key,
  value      text not null,
  updated_at timestamptz not null default now()
);
alter table public.admin_config enable row level security;
revoke all on public.admin_config from anon, authenticated;

-- -------------------------------------------------------------- throttle ---
create table if not exists public.admin_login_attempts (
  id           bigserial primary key,
  admin_name   text,
  ip           text,
  success      boolean not null default false,
  attempted_at timestamptz not null default now()
);
alter table public.admin_login_attempts enable row level security;
revoke all on public.admin_login_attempts from anon, authenticated;
create index if not exists admin_login_attempts_time_idx
  on public.admin_login_attempts (attempted_at);

-- ----------------------------------------------------------------- audit ---
-- Written ONLY from inside the SECURITY DEFINER functions below. An audit row
-- the client could write directly would be forgeable by anyone holding the
-- anon key, which would defeat the point. Read back through admin_list_audit().
create table if not exists public.admin_audit (
  id         bigserial primary key,
  at         timestamptz not null default now(),
  admin_name text not null,
  action     text not null,
  target     text,
  details    jsonb,
  source     text not null default 'rpc'
);
alter table public.admin_audit enable row level security;
revoke all on public.admin_audit from anon, authenticated;
create index if not exists admin_audit_at_idx on public.admin_audit (at desc);

-- -------------------------------------------------- reset_codes hygiene ----
-- Additive columns on the existing table. created_at already exists and is
-- already written; it has simply never been read. Now it is.
alter table public.reset_codes add column if not exists attempts   integer not null default 0;
alter table public.reset_codes add column if not exists created_by text;

-- ---------------------------------------------------- snapshots hygiene ----
-- deleted_users currently stores "a row that was deleted". The dashboard will
-- also snapshot BEFORE a progress reset, which is the undo for that action —
-- so the panel needs to say which is which. Additive with a default, so the
-- existing insert shape (user_name, data) keeps working untouched.
alter table public.deleted_users add column if not exists reason text default 'delete';

-- ============================================================================
-- Functions
-- ============================================================================

-- Client IP as reported by PostgREST's edge. Internal only. Spoofable in
-- principle, set by the edge in practice — a speed bump, not a boundary.
-- The bcrypt cost per attempt is the real backstop.
create or replace function public._admin_ip()
returns text
language plpgsql stable security definer
set search_path = public, extensions, pg_temp
as $$
declare v text;
begin
  begin
    v := current_setting('request.headers', true)::json->>'x-forwarded-for';
  exception when others then v := null;
  end;
  v := btrim(split_part(coalesce(v, ''), ',', 1));
  if v = '' then v := 'unknown'; end if;
  return left(v, 64);
end; $$;

-- Lazily create and return the HMAC signing key.
create or replace function public._admin_signing_key()
returns text
language plpgsql security definer
set search_path = public, extensions, pg_temp
as $$
declare v text;
begin
  select value into v from public.admin_config where key = 'token_key';
  if v is null then
    insert into public.admin_config (key, value)
    values ('token_key', encode(gen_random_bytes(32), 'hex'))
    on conflict (key) do nothing;
    select value into v from public.admin_config where key = 'token_key';
  end if;
  return v;
end; $$;

-- Issue a short-lived stateless token. No session table, nothing to clean up.
-- Revocation is by bumping admin_secrets.key_epoch, which invalidates all
-- outstanding tokens at once — coarse, but correct for a single admin, and it
-- still holds when named multi-admin is added because admin_name is inside the
-- signed payload.
create or replace function public._admin_issue_token(p_admin text, p_ttl_minutes integer default 45)
returns jsonb
language plpgsql security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_epoch   integer;
  v_exp     bigint;
  v_payload text;
begin
  select key_epoch into v_epoch from public.admin_secrets where admin_name = p_admin;
  if v_epoch is null then
    return jsonb_build_object('status', 'error');
  end if;
  v_exp     := extract(epoch from now())::bigint
               + greatest(1, least(coalesce(p_ttl_minutes, 45), 480)) * 60;
  v_payload := 'v1.' || v_epoch || '.' || p_admin || '.' || v_exp
               || '.' || encode(gen_random_bytes(8), 'hex');
  return jsonb_build_object(
    'status',     'ok',
    'token',      v_payload || '.' || encode(hmac(v_payload, public._admin_signing_key(), 'sha256'), 'hex'),
    'expires_at', to_timestamp(v_exp)
  );
end; $$;

-- Validate a token: returns the admin name, or null. Internal only — never
-- granted to anon, so there is no oracle for guessing tokens.
create or replace function public._admin_verify_token(p_token text)
returns text
language plpgsql security definer
set search_path = public, extensions, pg_temp
as $$
declare
  p         text[];
  v_payload text;
  v_admin   text;
  v_epoch   integer;
  v_exp     bigint;
  v_cur     integer;
begin
  if p_token is null or length(p_token) > 400 then return null; end if;
  p := string_to_array(p_token, '.');
  if array_length(p, 1) <> 6 or p[1] <> 'v1' then return null; end if;

  v_epoch   := p[2]::integer;
  v_admin   := p[3];
  v_exp     := p[4]::bigint;
  v_payload := array_to_string(p[1:5], '.');

  if encode(hmac(v_payload, public._admin_signing_key(), 'sha256'), 'hex') <> p[6] then
    return null;
  end if;
  if v_exp < extract(epoch from now())::bigint then return null; end if;

  select key_epoch into v_cur
    from public.admin_secrets
   where admin_name = v_admin and is_active;
  if v_cur is null or v_cur <> v_epoch then return null; end if;

  return v_admin;
exception when others then
  return null;
end; $$;

-- ------------------------------------------------------------- admin_login --
-- The only place the admin password is checked. Throttled, because this is now
-- an online oracle: without a limit, an attacker could grind it, and each
-- attempt also costs ~250 ms of database CPU (bcrypt cost 12), so throttling
-- doubles as a CPU-DoS control.
create or replace function public.admin_login(p_admin text, p_pass text)
returns jsonb
language plpgsql security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_admin  text := lower(btrim(coalesce(p_admin, '')));
  v_ip     text;
  v_hash   text;
  v_active boolean;
  v_fails  integer;
  v_global integer;
begin
  v_ip := public._admin_ip();

  -- Prune old throttle rows. Bounded to our own table.
  delete from public.admin_login_attempts where attempted_at < now() - interval '2 days';

  select count(*) into v_fails
    from public.admin_login_attempts
   where success = false
     and attempted_at > now() - interval '15 minutes'
     and (admin_name = v_admin or (v_ip <> 'unknown' and ip = v_ip));

  select count(*) into v_global
    from public.admin_login_attempts
   where success = false and attempted_at > now() - interval '15 minutes';

  if v_fails >= 8 or v_global >= 60 then
    insert into public.admin_login_attempts (admin_name, ip) values (v_admin, v_ip);
    return jsonb_build_object('status', 'throttled', 'retry_after_seconds', 900);
  end if;

  select pass_hash, is_active into v_hash, v_active
    from public.admin_secrets where admin_name = v_admin;

  if v_hash is null then
    -- Equal-cost burn so "no such admin" and "wrong password" take the same time.
    perform crypt(coalesce(p_pass, ''), gen_salt('bf', 12));
    insert into public.admin_login_attempts (admin_name, ip) values (v_admin, v_ip);
    return jsonb_build_object('status', 'bad_credentials');
  end if;

  if v_active and v_hash = crypt(coalesce(p_pass, ''), v_hash) then
    insert into public.admin_login_attempts (admin_name, ip, success) values (v_admin, v_ip, true);
    update public.admin_secrets set last_login_at = now() where admin_name = v_admin;
    insert into public.admin_audit (admin_name, action, target, details)
    values (v_admin, 'login', v_admin, jsonb_build_object('ip', v_ip));
    return jsonb_build_object('status', 'ok') || public._admin_issue_token(v_admin, 45);
  end if;

  insert into public.admin_login_attempts (admin_name, ip) values (v_admin, v_ip);
  return jsonb_build_object('status', 'bad_credentials');
end; $$;

-- ------------------------------------------------- request_reset (2 args) ---
-- New signature, token-gated. The old 1-argument version is deliberately left
-- in place until STAGE 3, so a browser holding a cached admin.html keeps
-- working through the deploy instead of breaking mid-switch.
--
-- Note: `create or replace` CANNOT change a signature — it would add an
-- overload and leave the insecure (text) version live. This is a new function,
-- and STAGE 3 drops the old one explicitly.
create or replace function public.request_reset(p_token text, p_user text)
returns jsonb
language plpgsql security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_admin text;
  v_name  text;
  v_code  text;
begin
  v_admin := public._admin_verify_token(p_token);
  if v_admin is null then
    return jsonb_build_object('status', 'unauthorized');
  end if;

  select user_name into v_name
    from public.progress
   where lower(user_name) = lower(btrim(coalesce(p_user, '')))
   limit 1;
  if v_name is null then
    return jsonb_build_object('status', 'no_user');
  end if;

  v_code := encode(gen_random_bytes(4), 'hex');   -- 8 hex chars, unchanged width

  insert into public.reset_codes (user_name, code, created_by, attempts)
  values (v_name, v_code, v_admin, 0)
  on conflict (user_name) do update
     set code       = excluded.code,
         created_at = now(),
         created_by = excluded.created_by,
         attempts   = 0;

  insert into public.admin_audit (admin_name, action, target)
  values (v_admin, 'reset_code_issued', v_name);

  return jsonb_build_object('status', 'ok', 'code', v_code);
end; $$;

-- ---------------------------------------------------- admin_list_resets ---
create or replace function public.admin_list_resets(p_token text)
returns jsonb
language plpgsql security definer
set search_path = public, extensions, pg_temp
as $$
declare v_admin text; v_out jsonb;
begin
  v_admin := public._admin_verify_token(p_token);
  if v_admin is null then return jsonb_build_object('status', 'unauthorized'); end if;

  select coalesce(jsonb_agg(jsonb_build_object(
           'user_name',  r.user_name,
           'created_at', r.created_at,
           'expires_at', r.created_at + interval '30 minutes',
           'expired',    r.created_at <= now() - interval '30 minutes',
           'attempts',   r.attempts,
           'created_by', r.created_by
         ) order by r.created_at desc), '[]'::jsonb)
    into v_out
    from public.reset_codes r;

  return jsonb_build_object('status', 'ok', 'codes', v_out);
end; $$;

-- -------------------------------------------------- admin_revoke_reset ----
create or replace function public.admin_revoke_reset(p_token text, p_user text)
returns jsonb
language plpgsql security definer
set search_path = public, extensions, pg_temp
as $$
declare v_admin text; v_name text;
begin
  v_admin := public._admin_verify_token(p_token);
  if v_admin is null then return jsonb_build_object('status', 'unauthorized'); end if;

  select user_name into v_name from public.progress
   where lower(user_name) = lower(btrim(coalesce(p_user, ''))) limit 1;
  if v_name is null then return jsonb_build_object('status', 'no_user'); end if;

  delete from public.reset_codes where user_name = v_name;   -- PK-qualified
  insert into public.admin_audit (admin_name, action, target)
  values (v_admin, 'reset_code_revoked', v_name);
  return jsonb_build_object('status', 'ok');
end; $$;

-- ------------------------------------------------ admin_change_password ---
create or replace function public.admin_change_password(p_token text, p_old text, p_new text)
returns jsonb
language plpgsql security definer
set search_path = public, extensions, pg_temp
as $$
declare v_admin text; v_hash text;
begin
  v_admin := public._admin_verify_token(p_token);
  if v_admin is null then return jsonb_build_object('status', 'unauthorized'); end if;
  if length(coalesce(p_new, '')) < 12 then
    return jsonb_build_object('status', 'weak_password');
  end if;

  select pass_hash into v_hash from public.admin_secrets where admin_name = v_admin;
  if v_hash is null or v_hash <> crypt(coalesce(p_old, ''), v_hash) then
    return jsonb_build_object('status', 'bad_credentials');
  end if;

  update public.admin_secrets
     set pass_hash = crypt(p_new, gen_salt('bf', 12)),
         key_epoch = key_epoch + 1,          -- invalidates every outstanding token
         updated_at = now()
   where admin_name = v_admin;

  insert into public.admin_audit (admin_name, action, target)
  values (v_admin, 'password_changed', v_admin);
  return jsonb_build_object('status', 'ok', 'reauth_required', true);
end; $$;

-- ---------------------------------------------------- admin_log_action ----
-- For dashboard actions that are still plain table writes (reset / delete /
-- restore a user). Token-gated, so an anon attacker cannot forge audit rows.
-- Best-effort: the client could skip the call. See the note in STAGE 3.
create or replace function public.admin_log_action(
  p_token text, p_action text, p_target text, p_details jsonb default '{}'::jsonb)
returns jsonb
language plpgsql security definer
set search_path = public, extensions, pg_temp
as $$
declare v_admin text;
begin
  v_admin := public._admin_verify_token(p_token);
  if v_admin is null then return jsonb_build_object('status', 'unauthorized'); end if;
  insert into public.admin_audit (admin_name, action, target, details, source)
  values (v_admin, left(coalesce(p_action, 'unknown'), 64),
          left(p_target, 200), coalesce(p_details, '{}'::jsonb), 'dashboard');
  return jsonb_build_object('status', 'ok');
end; $$;

-- ------------------------------------------------- admin_set_announcement --
-- Stores a message learners see as a banner. Written through here rather than
-- straight to app_settings so the write is token-gated AND guaranteed to work:
-- app_settings is readable with the anon key today, but nothing proves it is
-- writable, and a SECURITY DEFINER function bypasses that question entirely.
-- An empty string clears the banner.
create or replace function public.admin_set_announcement(p_token text, p_text text)
returns jsonb
language plpgsql security definer
set search_path = public, extensions, pg_temp
as $$
declare v_admin text; v_text text;
begin
  v_admin := public._admin_verify_token(p_token);
  if v_admin is null then return jsonb_build_object('status', 'unauthorized'); end if;

  v_text := left(btrim(coalesce(p_text, '')), 500);

  insert into public.app_settings (key, value) values ('announcement', v_text)
  on conflict (key) do update set value = excluded.value;

  insert into public.admin_audit (admin_name, action, target, details)
  values (v_admin, case when v_text = '' then 'announcement_cleared' else 'announcement_set' end,
          'announcement', jsonb_build_object('length', length(v_text)));

  return jsonb_build_object('status', 'ok');
end; $$;

-- ----------------------------------------------------- admin_list_audit ---
create or replace function public.admin_list_audit(p_token text, p_limit integer default 200)
returns jsonb
language plpgsql security definer
set search_path = public, extensions, pg_temp
as $$
declare v_admin text; v_out jsonb;
begin
  v_admin := public._admin_verify_token(p_token);
  if v_admin is null then return jsonb_build_object('status', 'unauthorized'); end if;

  select coalesce(jsonb_agg(x order by x->>'at' desc), '[]'::jsonb) into v_out
    from (
      select jsonb_build_object('at', at, 'admin', admin_name, 'action', action,
                                'target', target, 'details', details, 'source', source) as x
        from public.admin_audit
       order by at desc
       limit greatest(1, least(coalesce(p_limit, 200), 1000))
    ) s;

  return jsonb_build_object('status', 'ok', 'entries', v_out);
end; $$;

-- ------------------------------------------- reset_password (hardened) -----
-- SAME SIGNATURE as the live function, so `create or replace` works and
-- index.html needs no change. Two server-side additions:
--   * the code must be under 30 minutes old (created_at existed, unused until now)
--   * 5 wrong attempts delete the code
-- An expired code deliberately returns the EXISTING 'bad_code' status rather
-- than a new one: index.html (~733) has no branch for an unknown status and
-- would strand the nurse on "Resetting…". Better message later, isolated deploy.
create or replace function public.reset_password(p_user text, p_code text, p_new_pass text)
returns jsonb
language plpgsql security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_name  text;
  v_code  text;
  v_age   interval;
  v_tries integer;
  v_salt  text;
begin
  select user_name into v_name
    from public.progress
   where lower(user_name) = lower(btrim(coalesce(p_user, '')))
   limit 1;

  if v_name is null then
    return jsonb_build_object('status', 'no_user');
  end if;

  select code, (now() - created_at), coalesce(attempts, 0)
    into v_code, v_age, v_tries
    from public.reset_codes where user_name = v_name;

  if v_code is null then
    return jsonb_build_object('status', 'bad_code');
  end if;

  -- Expired codes are cleared so they cannot be retried.
  if v_age > interval '30 minutes' then
    delete from public.reset_codes where user_name = v_name;
    return jsonb_build_object('status', 'bad_code');
  end if;

  if v_code <> btrim(coalesce(p_code, '')) then
    v_tries := v_tries + 1;
    if v_tries >= 5 then
      delete from public.reset_codes where user_name = v_name;
    else
      update public.reset_codes set attempts = v_tries where user_name = v_name;
    end if;
    return jsonb_build_object('status', 'bad_code');
  end if;

  if coalesce(p_new_pass, '') = '' then
    return jsonb_build_object('status', 'invalid');
  end if;

  -- Store the new salted hash in the locked credentials table.
  v_salt := encode(gen_random_bytes(16), 'hex');
  insert into public.credentials (user_name, pass_salt, pass_hash)
  values (v_name, v_salt, encode(digest(v_salt || '::' || p_new_pass, 'sha256'), 'hex'))
  on conflict (user_name) do update
     set pass_salt  = excluded.pass_salt,
         pass_hash  = excluded.pass_hash,
         updated_at = now();

  -- Clear any legacy in-row hash/plaintext so the fallback path can't override.
  update public.progress
     set pass_hash = null, pass_salt = null, password = null
   where user_name = v_name;

  -- Single-use: consume the code.
  delete from public.reset_codes where user_name = v_name;

  return jsonb_build_object('status', 'ok');
end; $$;

-- ================================================================ grants ===
-- Privileged RPCs must be reachable by anon (that is all the dashboard has);
-- they self-authenticate with the token. The token check is the boundary.
revoke all on function public.admin_login(text, text)                   from public;
revoke all on function public.request_reset(text, text)                 from public;
revoke all on function public.admin_list_resets(text)                   from public;
revoke all on function public.admin_revoke_reset(text, text)            from public;
revoke all on function public.admin_change_password(text, text, text)   from public;
revoke all on function public.admin_log_action(text, text, text, jsonb) from public;
revoke all on function public.admin_list_audit(text, integer)           from public;
revoke all on function public.admin_set_announcement(text, text)        from public;
revoke all on function public.reset_password(text, text, text)          from public;

grant execute on function public.admin_login(text, text)                   to anon, authenticated;
grant execute on function public.request_reset(text, text)                 to anon, authenticated;
grant execute on function public.admin_list_resets(text)                   to anon, authenticated;
grant execute on function public.admin_revoke_reset(text, text)            to anon, authenticated;
grant execute on function public.admin_change_password(text, text, text)   to anon, authenticated;
grant execute on function public.admin_log_action(text, text, text, jsonb) to anon, authenticated;
grant execute on function public.admin_list_audit(text, integer)           to anon, authenticated;
grant execute on function public.admin_set_announcement(text, text)        to anon, authenticated;
grant execute on function public.reset_password(text, text, text)          to anon, authenticated;

-- Internal helpers: nobody. New functions default to EXECUTE for PUBLIC, so
-- this must be explicit or the token verifier would be callable by anyone.
revoke all on function public._admin_ip()                       from public, anon, authenticated;
revoke all on function public._admin_signing_key()              from public, anon, authenticated;
revoke all on function public._admin_issue_token(text, integer) from public, anon, authenticated;
revoke all on function public._admin_verify_token(text)         from public, anon, authenticated;


-- ============================================================================
-- STAGE 2 — pick the admin password. Run once, right after STAGE 1.
-- ============================================================================
-- Replace the placeholder below with the password you want to use from now on,
-- then run this statement. 12 characters minimum — admin_change_password
-- enforces that afterwards, so a shorter one here would be unusable to change.
--
-- It is bcrypt-hashed by Postgres, so the plaintext never lands in a table.
-- The `where not exists` guard means re-running this can never overwrite a
-- password you have already set.
--
-- NOTE: this REPLACES the old admin password. The old one keeps working only
-- until STAGE 3, and only through the OLD dashboard page — which is deliberate,
-- so you have a fallback if something goes wrong here.

insert into public.admin_secrets (admin_name, pass_hash)
select 'admin', crypt('REPLACE-WITH-A-STRONG-PASSWORD', gen_salt('bf', 12))
where not exists (select 1 from public.admin_secrets);

-- Confirm it landed (expect 1 row, and no readable hash anywhere public):
select admin_name, is_active, key_epoch, created_at from public.admin_secrets;


-- ============================================================================
-- STAGE 3 — RUN SEPARATELY, ONLY AFTER THE NEW admin.html IS LIVE AND VERIFIED
-- ============================================================================
-- Everything above is additive. This block is the only destructive part of the
-- file and is deliberately kept apart so it is never run by accident.
--
-- Wait at least 15 minutes after deploying the new dashboard: GitHub Pages
-- serves admin.html with max-age=600, so for up to 10 minutes a browser may
-- still hold the old page, which calls the 1-argument request_reset. Run this
-- too early and that cached page breaks.
--
-- Before running, note the current learner count so you can confirm it after:
--     select count(*) from public.progress;   -- expect 15
--
-- ---------------------------------------------------------------------------
-- 3a. Close the account-takeover: remove the anon-callable 1-arg request_reset.
--
--     The revoke must name `anon` explicitly. supabase-password-reset.sql:117
--     granted it to anon directly, and revoking from `public` alone does not
--     remove an explicit grant to a named role.
-- ---------------------------------------------------------------------------
-- revoke all on function public.request_reset(text) from anon, authenticated, public;
-- drop function if exists public.request_reset(text);

-- ---------------------------------------------------------------------------
-- 3b. Neutralise the world-readable admin verifier in app_settings.
--
--     DELETE the row rather than setting it to a placeholder. This matters:
--     the old dashboard falls back to a plaintext comparison when the stored
--     value contains no '::'. Setting it to 'disabled' would therefore let
--     anyone sign in by typing the word "disabled". Deleting the row makes the
--     old page fail closed with "Admin password not configured."
--
--     The old value is a fast sha256 the public key could already read, so it
--     is worthless once the row is gone — do not restore it. Capture it first
--     only if you want a record:
--         select value from public.app_settings where key = 'admin_password';
-- ---------------------------------------------------------------------------
-- delete from public.app_settings where key = 'admin_password';

-- ---------------------------------------------------------------------------
-- 3c. Verify. Expect 15 learners, and empty/permission-denied for the rest.
-- ---------------------------------------------------------------------------
-- select count(*) from public.progress;

--   curl -s -H "apikey: <ANON_KEY>" \
--     "https://ymvaslldugwzgjeaxabz.supabase.co/rest/v1/admin_secrets?select=*"
--   curl -s -H "apikey: <ANON_KEY>" \
--     "https://ymvaslldugwzgjeaxabz.supabase.co/rest/v1/reset_codes?select=*"
--   curl -s -X POST -H "apikey: <ANON_KEY>" -H "Content-Type: application/json" \
--     -d '{"p_user":"anybody"}' \
--     "https://ymvaslldugwzgjeaxabz.supabase.co/rest/v1/rpc/request_reset"
--     ^ expect a "function not found" error — the 1-arg version is gone.

-- ---------------------------------------------------------------------------
-- ROLLBACK (only if needed). Everything in STAGE 1 is additive, so undoing it
-- touches no learner data:
--   drop function if exists public.request_reset(text, text);
--   drop function if exists public.admin_login(text, text);
--   drop function if exists public.admin_list_resets(text);
--   drop function if exists public.admin_revoke_reset(text, text);
--   drop function if exists public.admin_change_password(text, text, text);
--   drop function if exists public.admin_log_action(text, text, text, jsonb);
--   drop function if exists public.admin_list_audit(text, integer);
--   drop function if exists public._admin_verify_token(text);
--   drop function if exists public._admin_issue_token(text, integer);
--   drop function if exists public._admin_signing_key();
--   drop function if exists public._admin_ip();
--   drop table if exists public.admin_audit, public.admin_login_attempts,
--                         public.admin_config, public.admin_secrets;
-- ---------------------------------------------------------------------------
-- KNOWN RESIDUALS — not fixed here, stated so they are not mistaken for fixed:
--
--   1. public.progress is world-readable AND world-writable with the anon key.
--      index.html inserts and upserts it directly from the browser (lines 820,
--      859, 995), so anyone can read, alter or erase any learner's row without
--      ever touching the dashboard. This is the largest remaining exposure and
--      it dwarfs the admin-password issue. Closing it means enabling RLS and
--      moving every learner write behind an RPC — a project in its own right.
--   2. public.deleted_users is likewise readable/writable and stores full row
--      snapshots, so delete-then-restore is also an exfiltration path.
--   3. reset_user / delete_user / restore_user in the dashboard are still plain
--      table writes; their audit rows come from a separate admin_log_action
--      call the client could skip. Converting them to token-gated RPCs is the
--      fix, and the plumbing for it now exists.
--   4. login_check is anon-callable with no rate limiting and no bcrypt, so it
--      is a fast password oracle for any named user. Arguably a bigger live
--      risk than the admin password was. Natural next step.
--   5. create_account is anon-callable by design, so unlimited accounts can be
--      created and progress inflated. Worth a cap later.
-- ============================================================================


-- ============================================================================
-- STAGE 4 — close the create_account account-takeover.
-- ============================================================================
-- Additive and idempotent, like STAGE 1. Safe to run on the live database.
--
-- This is a SEPARATE stage from STAGE 1-3 on purpose: those are already run and
-- verified, and this one touches nothing they touched except create_account.
--
-- THE BUG. create_account() guarded against duplicate names by reading
-- public.progress — a table the anon key can both read AND write — while the
-- insert it guards upserts public.credentials, which is locked. So:
--
--     DELETE /rest/v1/progress?user_name=eq.<nurse>      -- anon-writable
--     POST   /rpc/create_account {"p_user":"<nurse>", "p_pass":"attacker-chosen"}
--
-- The guard found no progress row, the `on conflict ... do update` then rewrote
-- the credential in the LOCKED table, and the attacker could log in as that
-- nurse. Locking a table does not help when the *guard* is the weak link.
--
-- The fix has three parts, and the third is easy to miss:
--   1. Guard on the locked table, matched case-insensitively (login resolves
--      names that way), and never overwrite: `on conflict ... do nothing`.
--   2. Move the delete behind a token-gated RPC, because the guard now consults
--      credentials — so a deleted learner's credential row has to be dealt with,
--      or the name could never be registered a second time.
--   3. PARK that credential row rather than snapshotting it. Snapshots live in
--      deleted_users, which is WORLD-READABLE — copying a hash there would
--      re-open the readable-hash hole closed on 2026-09-28. Renaming it keeps
--      the hash inside the locked table, frees the name, and lets Restore hand
--      back an account that still works.
-- ============================================================================


-- ---------------------------------------------------------------------------
-- 4a. A home for per-learner messages. Created here, ahead of the feature that
--     fills it, so that admin_delete_user below is complete in one place —
--     deleting a learner must take their messages with them.
-- ---------------------------------------------------------------------------
create table if not exists public.user_messages (
  id         bigserial primary key,
  user_name  text not null,
  body       text not null,
  created_by text not null,
  created_at timestamptz not null default now()
);
alter table public.user_messages enable row level security;
revoke all on public.user_messages from anon, authenticated;

-- Deliberately NO foreign key to progress. A declared FK is what lets PostgREST
-- embed one table inside another (`?select=*,user_messages(*)`); without it the
-- table cannot be reached that way at all. The lookup in login_check does not
-- need one. There is also only one canonical spelling per learner (see 5c).
create index if not exists user_messages_user_idx on public.user_messages (user_name, id desc);


-- ---------------------------------------------------------------------------
-- 4b. create_account, with the guard moved to the locked table.
--
--     Signature unchanged, so index.html needs no modification. SECURITY
--     DEFINER and search_path restated verbatim — `create or replace` swaps the
--     whole definition, and dropping either would change how it runs.
-- ---------------------------------------------------------------------------
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

  -- The authoritative check. Case-insensitive because login is: create_account
  -- stores the lowercased name, while rows that predate it keep their original
  -- spelling, and the roster has both.
  select c.user_name into v_existing
    from public.credentials c
   where lower(c.user_name) = v_name
   limit 1;

  -- Also refuse a name that is visibly somebody in the roster but has no
  -- credential row yet, so the roster cannot grow a second spelling of a name
  -- that is already on it.
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

  -- `do nothing`, not `do update`. Nothing above can legitimately reach an
  -- existing row any more, so if this ever does conflict it is a race or an
  -- attack — and silently taking the password over is the one thing that must
  -- not happen here.
  insert into public.credentials (user_name, pass_salt, pass_hash)
  values (v_name, v_salt, encode(digest(v_salt || '::' || p_pass, 'sha256'), 'hex'))
  on conflict (user_name) do nothing;

  get diagnostics v_rows = row_count;
  if v_rows = 0 then
    return jsonb_build_object('status', 'exists');
  end if;

  return jsonb_build_object('status', 'ok', 'user_name', v_name);
end;
$$;


-- ---------------------------------------------------------------------------
-- 4c. Deleting a learner, server-side, so the credential row goes with them.
--
--     Snapshots the profile in the SAME shape the dashboard already writes
--     (data = the progress row), so the Snapshots panel and every snapshot
--     taken before today keep working untouched.
-- ---------------------------------------------------------------------------
create or replace function public.admin_delete_user(p_token text, p_user text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_admin text;
  v_name  text;
  v_row   jsonb;
  v_id    bigint;
begin
  v_admin := public._admin_verify_token(p_token);
  if v_admin is null then return jsonb_build_object('status', 'unauthorized'); end if;

  select p.user_name into v_name
    from public.progress p
   where lower(p.user_name) = lower(btrim(coalesce(p_user, '')))
   limit 1;

  if v_name is null then
    return jsonb_build_object('status', 'no_user');
  end if;

  select to_jsonb(p) into v_row from public.progress p where p.user_name = v_name;

  insert into public.deleted_users (user_name, data, reason)
  values (v_name, v_row, 'delete')
  returning id into v_id;

  -- Park the credential row. See the stage header: this keeps the hash inside
  -- the locked table, makes the name registerable again, and lets Restore
  -- return an account whose password still works.
  update public.credentials
     set user_name = v_name || ' #deleted#' || v_id::text
   where user_name = v_name;

  delete from public.progress      where user_name = v_name;
  delete from public.user_messages where user_name = v_name;

  insert into public.admin_audit (admin_name, action, target, details)
  values (v_admin, 'delete_user', v_name,
          jsonb_build_object('snapshot_id', v_id,
                             'study_seconds', coalesce((v_row->>'study_seconds')::numeric, 0)));

  return jsonb_build_object('status', 'ok', 'snapshot_id', v_id);
end;
$$;


-- ---------------------------------------------------------------------------
-- 4d. Restoring a learner: un-park the credential row, then rebuild the profile
--     from the snapshot.
--
--     jsonb_populate_record maps only keys that match real columns and ignores
--     the rest, so this needs no knowledge of the progress schema — which is
--     important, because progress has no DDL anywhere in this repo.
-- ---------------------------------------------------------------------------
create or replace function public.admin_restore_user(p_token text, p_snapshot_id bigint)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_admin  text;
  v_name   text;
  v_data   jsonb;
  v_snap   bigint;
  v_parked text;
begin
  v_admin := public._admin_verify_token(p_token);
  if v_admin is null then return jsonb_build_object('status', 'unauthorized'); end if;

  select d.user_name, d.data, d.id into v_name, v_data, v_snap
    from public.deleted_users d
   where d.id = p_snapshot_id;

  if v_snap is null then
    return jsonb_build_object('status', 'no_snapshot');
  end if;

  -- A snapshot with no body would insert an all-null row and trip a constraint,
  -- which would read as a database fault rather than a bad snapshot.
  if v_data is null then
    return jsonb_build_object('status', 'bad_snapshot');
  end if;

  v_parked := v_name || ' #deleted#' || v_snap::text;

  -- Only un-park when there is a parked row AND nobody has taken the name
  -- since. If they have, the profile still restores and the learner sets a new
  -- password; clobbering the new holder's credential would be the same class of
  -- bug this stage exists to fix.
  if exists (select 1 from public.credentials c where c.user_name = v_parked)
     and not exists (select 1 from public.credentials c2 where c2.user_name = v_name) then
    update public.credentials set user_name = v_name where user_name = v_parked;
  end if;

  delete from public.progress where user_name = v_name;
  insert into public.progress select * from jsonb_populate_record(null::public.progress, v_data);

  delete from public.deleted_users where id = v_snap;

  insert into public.admin_audit (admin_name, action, target, details)
  values (v_admin, 'restore_user', v_name, jsonb_build_object('snapshot_id', v_snap));

  return jsonb_build_object('status', 'ok', 'snapshot_id', v_snap);
end;
$$;


-- ---------------------------------------------------------------------------
-- 4e. Grants. Privileged RPCs stay reachable by anon — that is all the
--     dashboard has — and prove identity with the token themselves.
-- ---------------------------------------------------------------------------
revoke all on function public.admin_delete_user(text, text)    from public;
revoke all on function public.admin_restore_user(text, bigint) from public;

grant execute on function public.admin_delete_user(text, text)    to anon, authenticated;
grant execute on function public.admin_restore_user(text, bigint) to anon, authenticated;

-- create_account keeps its existing grant; `create or replace` preserves the
-- ACL, and this restates it so that is not a thing anyone has to know.
revoke all on function public.create_account(text, text) from public;
grant execute on function public.create_account(text, text) to anon, authenticated;


-- ---------------------------------------------------------------------------
-- 4f. Verify. Run these after STAGE 4. All four must hold.
-- ---------------------------------------------------------------------------
-- Every one of the 15 learners still has exactly one credential row:
--   select count(*) from public.credentials where user_name not like '% #deleted#%';   -- expect 15
--
-- The takeover is closed. This is the decisive one, and it has to be run as a
-- transaction that ROLLS BACK, because it deliberately creates a throwaway
-- credential row to attack.
--
-- Why it works: create_account writes a credential row but NO progress row, so
-- __probe_tmp__ has exactly the shape an attacker manufactures by deleting a
-- victim's progress row — a credential row with nothing in progress to guard
-- it. Before this stage the second call returned 'ok' and took the account
-- over; now the guard reads the locked table and must refuse.
--
--   begin;
--     select public.create_account('__probe_tmp__', 'probe-pass-1');  -- expect ok
--     select public.create_account('__probe_tmp__', 'attacker-chosen'); -- expect exists
--   rollback;   -- nothing is kept; confirm with the count below
--
-- Do NOT test this with an existing learner's name. That returns 'exists'
-- whether or not the fix is in place — their progress row satisfies the old
-- guard too, so it proves nothing.
--
-- Nothing is parked yet, so this is 0 until the first delete:
--   select count(*) from public.credentials where user_name like '% #deleted#%';        -- expect 0
--
-- And after the rollback above, the throwaway is gone:
--   select count(*) from public.credentials where user_name = '__probe_tmp__';          -- expect 0
--
-- Both new RPCs exist and refuse a forged token:
--   select public.admin_delete_user('forged', 'ds');                                   -- unauthorized
--   select public.admin_restore_user('forged', 1);                                     -- unauthorized
-- ============================================================================


-- ============================================================================
-- STAGE 5 — a private message for one learner.
-- ============================================================================
-- Additive and idempotent. Safe to run on the live database, safe to re-run.
--
-- WHAT THIS IS. A note the admin writes to ONE named learner, shown to her in a
-- banner the next time she signs in.
--
-- THE WHOLE DESIGN PROBLEM: the naive version makes every private message
-- public. Learner names are not secret — public.progress is world-readable with
-- the anon key that ships inside index.html, so anyone can list all of them. A
-- messages table keyed by name and reachable through PostgREST with that same
-- key would let anyone read a note meant for one person. There is no application
-- server here and no session: index.html does not even keep the password after
-- sign-in (enterApp only stores the name).
--
-- THE ONE MOMENT THE APP CAN PROVE WHO A LEARNER IS is inside login_check(),
-- which already verifies the password and already returns that learner's
-- profile. So the message rides home on that response. That gives private
-- messaging with NO new client credential and NO new read path: the table below
-- is readable by nobody through the API, and its only reader is a function that
-- has already checked the password.
--
-- !! 5a RE-DECLARES login_check — THE HIGHEST-RISK EDIT IN THIS REPO. !!
-- It is the only door into the app. Read 5a's own comment before running it.
-- ============================================================================


-- ---------------------------------------------------------------------------
-- 5a. login_check, re-declared to carry the message home.
--
--     `create or replace` swaps the ENTIRE definition, so anything not restated
--     below is silently lost. Three things must be restated verbatim:
--
--       * `security definer` — otherwise the function runs as the caller (anon)
--         and cannot read the locked credentials table at all, and every login
--         in the app fails.
--       * `set search_path = public, extensions, pg_temp` — otherwise digest()
--         and gen_random_bytes() stop resolving.
--       * The parameter NAMES p_user / p_pass — PostgREST resolves named
--         arguments, so renaming them breaks the client without any error here.
--
--     Everything between here and the two additions is byte-identical to the
--     live definition in supabase-auth-hardening.sql: the same three verification
--     branches (a) hash in the locked table, (b) hash still in the progress row,
--     (c) legacy plaintext, the same no_user / bad_password returns, and the same
--     profile select. Only two things are new: the v_messages declaration, and
--     'messages' added to the object returned at the end.
--
--     The messages read sits AFTER the `if not v_ok` gate. That ordering IS the
--     privacy claim: no correct password, no message.
--
--     'messages' is a SIBLING of 'profile', never a key inside it — enterApp()
--     hands window.userProgress (= srv.profile) to saveLocal(), so a key inside
--     profile would be written into the learner's local cache.
-- ---------------------------------------------------------------------------
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
  v_messages jsonb;
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

  -- (a) normal case: hash lives in the locked table
  if v_chash is not null
     and v_chash = encode(digest(coalesce(v_csalt, '') || '::' || p_pass, 'sha256'), 'hex') then
    v_ok := true;

  -- (b) hash still in the progress row (pre-migration, or just written by the
  --     admin reset button): verify it, then move it somewhere unreadable.
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

  -- (c) legacy plaintext: verify it, then store a salted hash instead
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

  -- ------- the only new behaviour: the newest message, after the gate -------
  -- Keyed on v_name — the EXACT stored spelling that was just authenticated
  -- against. One pair of names in this roster differs only in case, so a
  -- case-insensitive match here would hand one learner's note to whoever holds
  -- the other one's password.
  --
  -- The exception block is deliberate insurance, not decoration. This function
  -- is the only way into the app, and if it raises, index.html's serverLogin
  -- returns null and EVERY learner is silently told her correct password is
  -- wrong. So a missing user_messages table degrades to "no message" rather
  -- than to "nobody can sign in" — which is what running STAGE 5 without
  -- STAGE 4 would otherwise do, given it takes about ten seconds to do that.
  begin
    select jsonb_build_object('id', m.id, 'body', m.body, 'created_at', m.created_at)
      into v_messages
      from public.user_messages m
     where m.user_name = v_name
     order by m.id desc
     limit 1;
  exception when undefined_table then
    v_messages := null;
  end;

  select to_jsonb(p) - 'pass_hash' - 'pass_salt' - 'password'
    into v_profile
    from public.progress p
   where p.user_name = v_name;

  return jsonb_build_object('status', 'ok', 'profile', v_profile, 'messages', v_messages);
end;
$$;

-- `create or replace` preserves the existing ACL, but restating it costs nothing
-- and removes the doubt. Mirrors supabase-auth-hardening.sql.
revoke all on function public.login_check(text, text) from public;
grant execute on function public.login_check(text, text) to anon, authenticated;


-- ---------------------------------------------------------------------------
-- 5b. admin_list_messages — the outstanding note for one learner, for the
--     dashboard's user sheet. `message` is null when there is none, and `count`
--     is how many rows exist (the sheet clears them all, the learner sees one).
-- ---------------------------------------------------------------------------
create or replace function public.admin_list_messages(p_token text, p_user text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_admin text;
  v_name  text;
  v_msg   jsonb;
  v_count integer;
begin
  v_admin := public._admin_verify_token(p_token);
  if v_admin is null then return jsonb_build_object('status', 'unauthorized'); end if;

  -- Resolve to the canonical spelling stored in progress, so the key used here
  -- is exactly the one login_check will look up.
  select p.user_name into v_name
    from public.progress p
   where lower(p.user_name) = lower(btrim(coalesce(p_user, '')))
   limit 1;

  if v_name is null then return jsonb_build_object('status', 'no_user'); end if;

  select count(*) into v_count from public.user_messages where user_name = v_name;

  select jsonb_build_object('id', m.id, 'body', m.body,
                            'created_at', m.created_at, 'created_by', m.created_by)
    into v_msg
    from public.user_messages m
   where m.user_name = v_name
   order by m.id desc
   limit 1;

  return jsonb_build_object('status', 'ok', 'message', v_msg, 'count', v_count);
end; $$;


-- ---------------------------------------------------------------------------
-- 5c. admin_send_message — writes the note. Appends rather than replaces, so
--     "Clear" in the dashboard clears all of a learner's messages and each send
--     is auditable on its own.
-- ---------------------------------------------------------------------------
create or replace function public.admin_send_message(p_token text, p_user text, p_text text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_admin text;
  v_name  text;
  v_text  text;
  v_id    bigint;
begin
  v_admin := public._admin_verify_token(p_token);
  if v_admin is null then return jsonb_build_object('status', 'unauthorized'); end if;

  select p.user_name into v_name
    from public.progress p
   where lower(p.user_name) = lower(btrim(coalesce(p_user, '')))
   limit 1;

  if v_name is null then return jsonb_build_object('status', 'no_user'); end if;

  -- Same 500-character cap the announcement uses.
  v_text := left(btrim(coalesce(p_text, '')), 500);
  if v_text = '' then return jsonb_build_object('status', 'empty'); end if;

  insert into public.user_messages (user_name, body, created_by)
  values (v_name, v_text, v_admin)
  returning id into v_id;

  -- Length, not content: the message already lives in user_messages, and an
  -- audit trail is about who did what, not a second copy of the text.
  insert into public.admin_audit (admin_name, action, target, details)
  values (v_admin, 'message_sent', v_name,
          jsonb_build_object('message_id', v_id, 'length', length(v_text)));

  return jsonb_build_object('status', 'ok', 'message_id', v_id);
end; $$;


-- ---------------------------------------------------------------------------
-- 5d. admin_clear_message — removes every message for one learner.
-- ---------------------------------------------------------------------------
create or replace function public.admin_clear_message(p_token text, p_user text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_admin text;
  v_name  text;
  v_n     integer;
begin
  v_admin := public._admin_verify_token(p_token);
  if v_admin is null then return jsonb_build_object('status', 'unauthorized'); end if;

  select p.user_name into v_name
    from public.progress p
   where lower(p.user_name) = lower(btrim(coalesce(p_user, '')))
   limit 1;

  if v_name is null then return jsonb_build_object('status', 'no_user'); end if;

  delete from public.user_messages where user_name = v_name;
  get diagnostics v_n = row_count;

  insert into public.admin_audit (admin_name, action, target, details)
  values (v_admin, 'message_cleared', v_name, jsonb_build_object('cleared', v_n));

  return jsonb_build_object('status', 'ok', 'cleared', v_n);
end; $$;


-- ---------------------------------------------------------------------------
-- 5e. Grants. Privileged RPCs stay reachable by anon — that is all the dashboard
--     has — and prove identity themselves with the token. The token check is the
--     boundary; the grant is not.
-- ---------------------------------------------------------------------------
revoke all on function public.admin_list_messages(text, text)        from public;
revoke all on function public.admin_send_message(text, text, text)   from public;
revoke all on function public.admin_clear_message(text, text)        from public;

grant execute on function public.admin_list_messages(text, text)      to anon, authenticated;
grant execute on function public.admin_send_message(text, text, text) to anon, authenticated;
grant execute on function public.admin_clear_message(text, text)      to anon, authenticated;


-- ---------------------------------------------------------------------------
-- 5f. Verify. Run these after STAGE 5.
-- ---------------------------------------------------------------------------
-- The table is still readable by nobody through the API (expect 401, which is
-- "exists and locked" — a 404 would mean it is not there at all):
--   --   curl -s -o /dev/null -w '%{http_code}\n' \
--   --     -H "apikey: <ANON_KEY>" "https://<project>.supabase.co/rest/v1/user_messages?select=id"
--
-- Logins still work. This is the one that matters most, because 5a re-declared
-- the function every learner signs in through. Use a real learner and her real
-- password, and expect status ok:
--   select public.login_check('<a real learner>', '<her password>');   -- ok
--   select public.login_check('<a real learner>', 'definitely-wrong'); -- bad_password
--   select public.login_check('nobody at all', 'x');                    -- no_user
--
-- The three new RPCs exist and refuse a forged token:
--   select public.admin_list_messages('forged', 'ds');       -- unauthorized
--   select public.admin_send_message('forged', 'ds', 'hi');  -- unauthorized
--   select public.admin_clear_message('forged', 'ds');       -- unauthorized
--
-- The privacy claim, end to end. Send a note to a throwaway learner, then read
-- back with the WRONG password and with a DIFFERENT learner — both must come
-- back with no message at all:
--
--   select public.admin_send_message('<a real admin token>', '__probe_msg__', 'hello');
--   -- as the learner, with her password: messages is the note
--   select public.login_check('__probe_msg__', 'her-password') -> 'messages';
--   -- with a wrong password: bad_password, and no messages key at all
--   select public.login_check('__probe_msg__', 'wrong');
--   -- as a different learner: messages is null
--   select public.login_check('<someone else>', '<her password>') -> 'messages';
--
-- Then clean up, so no probe rows are left behind:
--   delete from public.user_messages where user_name = '__probe_msg__';
--   delete from public.credentials   where user_name = '__probe_msg__';
--   delete from public.progress      where user_name = '__probe_msg__';
-- ============================================================================
