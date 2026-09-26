-- ============================================================================
-- CNN Study App — credential hardening
-- ============================================================================
-- WHY
--   Today the browser verifies passwords by reading pass_hash / pass_salt out
--   of the `progress` table using the public anon key. That key ships inside
--   index.html, so anyone who views the page source can read every account's
--   password hash and crack it offline.
--
-- WHAT THIS DOES
--   Moves the secrets into a table the anon key cannot read, and verifies
--   passwords inside the database. The hash never leaves Postgres.
--
-- WHY IT DOES NOT BREAK LOGIN
--   STAGE 1 is purely additive: it creates objects and copies data. It changes
--   nothing the running app does. Nothing starts using it until the matching
--   client change is deployed, and that client falls back to the old path if
--   these functions are missing. login_check also still accepts a hash found in
--   `progress`, so the admin "reset password" button keeps working as-is.
--
-- RUN ORDER
--   STAGE 1  ->  deploy the client  ->  wait 15+ min  ->  STAGE 3
--
--   The 15 minute wait matters: GitHub Pages caches index.html for 10 minutes
--   (cache-control: max-age=600). A page from the old cache verifies passwords
--   client-side against `progress`, so STAGE 3 must not run until stale pages
--   have expired, or those users cannot sign in.
-- ============================================================================

-- pgcrypto supplies digest() and gen_random_bytes(). On Supabase it usually
-- lives in the `extensions` schema, which is why the functions below include
-- `extensions` in their search_path. Harmless if it is already installed.
create extension if not exists pgcrypto with schema extensions;


-- ============================================================== STAGE 1 =====
-- Additive only. Safe to run on the live database, safe to re-run.

-- 1. Secrets get their own table.
create table if not exists public.credentials (
  user_name  text primary key,
  pass_salt  text,
  pass_hash  text,
  updated_at timestamptz not null default now()
);

-- 2. Lock it down. RLS enabled with NO policies means the anon key reads
--    nothing at all from this table.
alter table public.credentials enable row level security;
revoke all on public.credentials from anon, authenticated;

-- 3. Copy the existing hashes across. Idempotent.
insert into public.credentials (user_name, pass_salt, pass_hash)
select user_name, pass_salt, pass_hash
  from public.progress
 where user_name is not null
   and (pass_hash is not null or pass_salt is not null)
on conflict (user_name) do update
   set pass_salt  = excluded.pass_salt,
       pass_hash  = excluded.pass_hash,
       updated_at = now();

-- 4. Verify a password inside the database and return the profile WITHOUT any
--    credential columns. Accepts a hash from either location and migrates an
--    in-row hash into the locked table, which is what lets the admin reset
--    button keep working without modification.
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

  select to_jsonb(p) - 'pass_hash' - 'pass_salt' - 'password'
    into v_profile
    from public.progress p
   where p.user_name = v_name;

  return jsonb_build_object('status', 'ok', 'profile', v_profile);
end;
$$;

-- 5. Register the credential record for a brand-new account. The client still
--    writes its own profile row, so this needs no knowledge of that schema.
--    Idempotent: re-running before the profile row exists returns 'ok' again,
--    so a failed profile insert can simply be retried.
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
begin
  if v_name = '' or coalesce(p_pass, '') = '' then
    return jsonb_build_object('status', 'invalid');
  end if;

  select user_name into v_existing
    from public.progress
   where lower(user_name) = v_name
   limit 1;

  if v_existing is not null then
    return jsonb_build_object('status', 'exists');
  end if;

  v_salt := encode(gen_random_bytes(16), 'hex');
  insert into public.credentials (user_name, pass_salt, pass_hash)
  values (v_name, v_salt, encode(digest(v_salt || '::' || p_pass, 'sha256'), 'hex'))
  on conflict (user_name) do update
     set pass_salt  = excluded.pass_salt,
         pass_hash  = excluded.pass_hash,
         updated_at = now();

  return jsonb_build_object('status', 'ok', 'user_name', v_name);
end;
$$;

-- 6. Expose exactly these two to the anon key, and nothing else.
revoke all on function public.login_check(text, text)   from public;
revoke all on function public.create_account(text, text) from public;
grant execute on function public.login_check(text, text)   to anon, authenticated;
grant execute on function public.create_account(text, text) to anon, authenticated;


-- ============================================================== VERIFY ======
-- Run these after STAGE 1, before deploying anything. They must all be true.
--
--   -- every account with a hash has a credentials row
--   select count(*) as missing
--     from public.progress p
--     left join public.credentials c on c.user_name = p.user_name
--    where p.pass_hash is not null and c.pass_hash is null;
--   -- expect 0
--
--   -- the hashes match between the two tables
--   select count(*) as mismatched
--     from public.progress p
--     join public.credentials c on c.user_name = p.user_name
--    where p.pass_hash is distinct from c.pass_hash;
--   -- expect 0
--
--   -- the table really is unreadable with the public key
--   --   curl -s -H "apikey: <ANON_KEY>" \
--   --     "https://<project>.supabase.co/rest/v1/credentials?select=*"
--   -- expect [] or a permission error, never any rows
--
--   -- the function works (use a throwaway account, then delete it)
--   select public.login_check('someuser', 'theirpassword');   -- status ok
--   select public.login_check('someuser', 'wrong');           -- bad_password
--   select public.login_check('nobody', 'x');                 -- no_user


-- ============================================================== STAGE 3 =====
-- Run ONLY after the client change is live AND logins have been confirmed.
-- This is the step that actually closes the exposure: it clears the hashes
-- from the table the anon key can read. The hashes are preserved in
-- public.credentials, so this is reversible.

update public.progress
   set pass_hash = null,
       pass_salt = null,
       password  = null;

-- ROLLBACK (if anything is wrong, put the hashes back):
--
--   update public.progress p
--      set pass_hash = c.pass_hash,
--          pass_salt = c.pass_salt
--     from public.credentials c
--    where c.user_name = p.user_name;
