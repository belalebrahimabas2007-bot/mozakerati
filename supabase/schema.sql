-- مذاكرتي: Supabase schema
-- Run this file once in Supabase Dashboard -> SQL Editor.
-- Safe to run again for policies/functions; table creation is guarded.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  stage text not null default '',
  city text not null default '',
  role text not null default 'student' check (role in ('student','admin')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.stages (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  slug text not null unique,
  sort_order int not null default 0,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.subjects (
  id uuid primary key default gen_random_uuid(),
  stage_id uuid not null references public.stages(id) on delete cascade,
  name text not null,
  sort_order int not null default 0,
  is_published boolean not null default true,
  created_at timestamptz not null default now(),
  unique(stage_id, name)
);

create table if not exists public.units (
  id uuid primary key default gen_random_uuid(),
  subject_id uuid not null references public.subjects(id) on delete cascade,
  name text not null,
  sort_order int not null default 0,
  is_published boolean not null default true,
  created_at timestamptz not null default now(),
  unique(subject_id, name)
);

create table if not exists public.lessons (
  id uuid primary key default gen_random_uuid(),
  unit_id uuid not null references public.units(id) on delete cascade,
  name text not null,
  sort_order int not null default 0,
  difficulty smallint not null default 2 check (difficulty between 1 and 3),
  is_published boolean not null default true,
  created_at timestamptz not null default now(),
  unique(unit_id, name)
);

create table if not exists public.lesson_progress (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  lesson_id uuid not null references public.lessons(id) on delete cascade,
  last_studied_at timestamptz,
  review_step int not null default 0 check (review_step between 0 and 4),
  understanding smallint check (understanding between 1 and 3),
  updated_at timestamptz not null default now(),
  unique(user_id, lesson_id)
);

create table if not exists public.tasks (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  is_done boolean not null default false,
  kind text not null default 'other' check (kind in ('study','review','other')),
  lesson_id uuid references public.lessons(id) on delete set null,
  due_at timestamptz,
  created_at timestamptz not null default now(),
  completed_at timestamptz
);

create table if not exists public.study_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  kind text not null check (kind in ('study','review','focus')),
  lesson_id uuid references public.lessons(id) on delete set null,
  minutes int check (minutes is null or minutes > 0),
  created_at timestamptz not null default now()
);

create table if not exists public.announcements (
  id uuid primary key default gen_random_uuid(),
  title text not null default '',
  body text not null,
  target_stage text,
  is_published boolean not null default true,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create index if not exists subjects_stage_idx on public.subjects(stage_id, sort_order);
create index if not exists units_subject_idx on public.units(subject_id, sort_order);
create index if not exists lessons_unit_idx on public.lessons(unit_id, sort_order);
create index if not exists progress_user_idx on public.lesson_progress(user_id);
create index if not exists tasks_user_idx on public.tasks(user_id, created_at desc);
create index if not exists logs_user_idx on public.study_logs(user_id, created_at desc);
create index if not exists announcements_stage_idx on public.announcements(target_stage, created_at desc);

-- Admin check is SECURITY DEFINER to avoid recursive profile RLS.
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.role = 'admin'
  );
$$;

revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to authenticated;

-- Create a student profile automatically on sign-up.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name, stage, city)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'full_name', ''),
    coalesce(new.raw_user_meta_data ->> 'stage', ''),
    coalesce(new.raw_user_meta_data ->> 'city', '')
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_mozakerati on auth.users;
create trigger on_auth_user_created_mozakerati
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- Keep role immutable for users updating their own profile.
create or replace function public.prevent_profile_role_change()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.role is distinct from old.role and not public.is_admin() then
    raise exception 'Only an administrator can change profile roles';
  end if;
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists profiles_role_guard on public.profiles;
create trigger profiles_role_guard
before update on public.profiles
for each row execute procedure public.prevent_profile_role_change();

alter table public.profiles enable row level security;
alter table public.stages enable row level security;
alter table public.subjects enable row level security;
alter table public.units enable row level security;
alter table public.lessons enable row level security;
alter table public.lesson_progress enable row level security;
alter table public.tasks enable row level security;
alter table public.study_logs enable row level security;
alter table public.announcements enable row level security;

-- Profiles: users can see/edit their own profile; admins can see/manage all.
drop policy if exists "profile read own or admin" on public.profiles;
create policy "profile read own or admin" on public.profiles
for select to authenticated
using (id = (select auth.uid()) or public.is_admin());

drop policy if exists "profile update own or admin" on public.profiles;
create policy "profile update own or admin" on public.profiles
for update to authenticated
using (id = (select auth.uid()) or public.is_admin())
with check (id = (select auth.uid()) or public.is_admin());

-- Public curriculum: only active/published records are visible to signed-in students.
drop policy if exists "stages read active or admin" on public.stages;
create policy "stages read active or admin" on public.stages
for select to authenticated
using (is_active or public.is_admin());

drop policy if exists "stages admin manage" on public.stages;
create policy "stages admin manage" on public.stages
for all to authenticated
using (public.is_admin()) with check (public.is_admin());

drop policy if exists "subjects read published or admin" on public.subjects;
create policy "subjects read published or admin" on public.subjects
for select to authenticated
using (
  public.is_admin() or (
    is_published and exists (
      select 1 from public.stages st where st.id = stage_id and st.is_active
    )
  )
);

drop policy if exists "subjects admin manage" on public.subjects;
create policy "subjects admin manage" on public.subjects
for all to authenticated
using (public.is_admin()) with check (public.is_admin());

drop policy if exists "units read published or admin" on public.units;
create policy "units read published or admin" on public.units
for select to authenticated
using (
  public.is_admin() or (
    is_published and exists (
      select 1 from public.subjects s
      join public.stages st on st.id = s.stage_id
      where s.id = subject_id and s.is_published and st.is_active
    )
  )
);

drop policy if exists "units admin manage" on public.units;
create policy "units admin manage" on public.units
for all to authenticated
using (public.is_admin()) with check (public.is_admin());

drop policy if exists "lessons read published or admin" on public.lessons;
create policy "lessons read published or admin" on public.lessons
for select to authenticated
using (
  public.is_admin() or (
    is_published and exists (
      select 1 from public.units u
      join public.subjects s on s.id = u.subject_id
      join public.stages st on st.id = s.stage_id
      where u.id = unit_id and u.is_published and s.is_published and st.is_active
    )
  )
);

drop policy if exists "lessons admin manage" on public.lessons;
create policy "lessons admin manage" on public.lessons
for all to authenticated
using (public.is_admin()) with check (public.is_admin());

-- Private student data: each student only accesses their own rows; admins can manage all.
drop policy if exists "progress own or admin" on public.lesson_progress;
create policy "progress own or admin" on public.lesson_progress
for all to authenticated
using (user_id = (select auth.uid()) or public.is_admin())
with check (user_id = (select auth.uid()) or public.is_admin());

drop policy if exists "tasks own or admin" on public.tasks;
create policy "tasks own or admin" on public.tasks
for all to authenticated
using (user_id = (select auth.uid()) or public.is_admin())
with check (user_id = (select auth.uid()) or public.is_admin());

drop policy if exists "logs own or admin" on public.study_logs;
create policy "logs own or admin" on public.study_logs
for all to authenticated
using (user_id = (select auth.uid()) or public.is_admin())
with check (user_id = (select auth.uid()) or public.is_admin());

drop policy if exists "announcements read target or admin" on public.announcements;
create policy "announcements read target or admin" on public.announcements
for select to authenticated
using (
  public.is_admin() or (
    is_published and (
      target_stage is null or target_stage = (
        select p.stage from public.profiles p where p.id = (select auth.uid())
      )
    )
  )
);

drop policy if exists "announcements admin manage" on public.announcements;
create policy "announcements admin manage" on public.announcements
for all to authenticated
using (public.is_admin()) with check (public.is_admin());

-- Authenticated users may read the curriculum and operate only on RLS-protected rows.
grant usage on schema public to authenticated;
grant select on public.stages, public.subjects, public.units, public.lessons, public.announcements to authenticated;
grant select, update on public.profiles to authenticated;
grant select, insert, update, delete on public.lesson_progress, public.tasks, public.study_logs to authenticated;
grant insert, update, delete on public.stages, public.subjects, public.units, public.lessons, public.announcements to authenticated;

-- Initial stages; add subjects/units/lessons from the admin dashboard after integration.
insert into public.stages (name, slug, sort_order)
values
  ('تاسع', 'grade-9', 1),
  ('بكالوريا علمي', 'baccalaureate-scientific', 2),
  ('بكالوريا أدبي', 'baccalaureate-literary', 3),
  ('جامعة', 'university', 4)
on conflict (slug) do nothing;
