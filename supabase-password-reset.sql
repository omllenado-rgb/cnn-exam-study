-- ============================================================================
-- CNN Study App — self-service password reset (Option A)
-- ============================================================================
-- FLOW
--   1. Admin clicks "Reset PW" -> request_reset() generates a one-time 8-char
--      code and returns it, so the admin can share it with the nurse.
--   2. Nurse opens the app -> "Forgot password?" -> enters name + code + a new
--      password -> reset_password() verifies the code and stores the new hash.
--
-- WHY SERVER-SIDE
--   The reset code must not be readable with the public anon key (which ships
--   in index.html). Both functions are SECURITY DEFINER and the code lives in
--   a locked table, so the code and the password hash never leave Postgres.
--
-- IDEMPOTENT: safe to run / re-run on the live database.
-- ============================================================================

-- pgcrypto supplies digest() and gen_random_bytes() (already installed by the
-- credential-hardening SQL, but re-asserting is harmless).
create extension if not exists pgcrypto with schema extensions;

-- 1. Reset codes get their own locked table (single-use, one per user).
create table if not exists public.reset_codes (
  user_name  text primary key,
  code       text not null,
  created_at timestamptz not null default now()
);
alter table public.reset_codes enable row level security;
revoke all on public.reset_codes from anon, authenticated;

-- 2. Generate (or regenerate) a one-time code for a user and return it.
create or replace function public.request_reset(p_user text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_name text;
  v_code text;
begin
  select user_name into v_name
    from public.progress
   where lower(user_name) = lower(btrim(coalesce(p_user, '')))
   limit 1;

  if v_name is null then
    return jsonb_build_object('status', 'no_user');
  end if;

  -- 4 random bytes -> 8 hex characters (e.g. "a3f9c2d1")
  v_code := encode(gen_random_bytes(4), 'hex');

  insert into public.reset_codes (user_name, code)
  values (v_name, v_code)
  on conflict (user_name) do update
     set code = excluded.code, created_at = now();

  return jsonb_build_object('status', 'ok', 'code', v_code);
end;
$$;

-- 3. Verify the code and set the new password (single-use: code is deleted).
create or replace function public.reset_password(p_user text, p_code text, p_new_pass text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_name  text;
  v_code  text;
  v_salt  text;
begin
  select user_name into v_name
    from public.progress
   where lower(user_name) = lower(btrim(coalesce(p_user, '')))
   limit 1;

  if v_name is null then
    return jsonb_build_object('status', 'no_user');
  end if;

  select code into v_code from public.reset_codes where user_name = v_name;
  if v_code is null or v_code <> btrim(coalesce(p_code, '')) then
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
end;
$$;

-- 4. Expose exactly these two functions to the anon key, nothing else.
revoke all on function public.request_reset(text)   from public;
revoke all on function public.reset_password(text, text, text) from public;
grant execute on function public.request_reset(text)   to anon, authenticated;
grant execute on function public.reset_password(text, text, text) to anon, authenticated;
