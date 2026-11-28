-- 職業安全衛生乙級智慧互動學習系統：UUID 管理者授權與稽核
-- 在 Supabase SQL Editor 以專案管理者身分完整執行。
-- 本腳本將目前指定管理者 email 對應到 auth.users.id，僅將 UUID 寫入私有授權表。
-- 前端只呼叫公開 RPC；管理者身分與所有資料讀取均在資料庫端以 auth.uid() 驗證。

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table if not exists private.teacher_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists private.teacher_audit_logs (
  id bigint generated always as identity primary key,
  actor_id uuid not null references auth.users(id) on delete cascade,
  action text not null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

revoke all on all tables in schema private from public, anon, authenticated;
revoke all on all sequences in schema private from public, anon, authenticated;

-- 學生端資料隔離：每個登入帳號只能讀寫自己的學習資料。
alter table public.oshb_learning_data enable row level security;

-- 移除該資料表既有政策，避免舊的寬鬆政策與新政策以 OR 合併造成越權。
do $
declare
  policy_row record;
begin
  for policy_row in
    select policyname
    from pg_policies
    where schemaname = 'public'
      and tablename = 'oshb_learning_data'
  loop
    execute format('drop policy if exists %I on public.oshb_learning_data', policy_row.policyname);
  end loop;
end;
$;

drop policy if exists "students_select_own_learning_data" on public.oshb_learning_data;
create policy "students_select_own_learning_data"
on public.oshb_learning_data
for select
to authenticated
using (auth.uid() = user_id);

drop policy if exists "students_insert_own_learning_data" on public.oshb_learning_data;
create policy "students_insert_own_learning_data"
on public.oshb_learning_data
for insert
to authenticated
with check (auth.uid() = user_id);

drop policy if exists "students_update_own_learning_data" on public.oshb_learning_data;
create policy "students_update_own_learning_data"
on public.oshb_learning_data
for update
to authenticated
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

revoke all on table public.oshb_learning_data from anon;
grant select, insert, update on table public.oshb_learning_data to authenticated;

-- 僅在部署時以管理者執行：將指定帳號轉成 UUID 白名單。
do $$
declare
  v_admin_id uuid;
begin
  select id into v_admin_id
  from auth.users
  where lower(email) = 'ycc0824@gmail.com'
  limit 1;

  if v_admin_id is null then
    raise exception '找不到管理者帳號 ycc0824@gmail.com。請先使用此信箱註冊並完成登入驗證，再重新執行 SQL。';
  end if;

  delete from private.teacher_admins;
  insert into private.teacher_admins(user_id) values (v_admin_id);
end;
$$;

create or replace function public.is_teacher_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from private.teacher_admins a
    where a.user_id = auth.uid()
  );
$$;

create or replace function public.teacher_log_event(
  p_action text,
  p_details jsonb default '{}'::jsonb
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or not exists (
    select 1 from private.teacher_admins a where a.user_id = auth.uid()
  ) then
    raise exception 'permission denied: teacher access is restricted';
  end if;

  if p_action not in ('login','logout','dashboard_view','student_data_read','refresh','student_record_update','settings_change') then
    raise exception 'unsupported audit action';
  end if;

  insert into private.teacher_audit_logs(actor_id,action,details)
  values (auth.uid(),p_action,coalesce(p_details,'{}'::jsonb));

  return true;
end;
$$;

create or replace function public.teacher_dashboard_data()
returns table (
  student_id uuid,
  student_email text,
  data jsonb,
  updated_at timestamptz
)
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or not exists (
    select 1 from private.teacher_admins a where a.user_id = auth.uid()
  ) then
    raise exception 'permission denied: teacher access is restricted';
  end if;

  insert into private.teacher_audit_logs(actor_id,action,details)
  values (auth.uid(),'student_data_read','{"source":"teacher_dashboard"}'::jsonb);

  return query
  select d.user_id, u.email::text, d.data, d.updated_at
  from public.oshb_learning_data as d
  left join auth.users as u on u.id = d.user_id
  order by d.updated_at desc nulls last;
end;
$$;

create or replace function public.teacher_audit_logs()
returns table (
  id bigint,
  actor_email text,
  action text,
  details jsonb,
  created_at timestamptz
)
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or not exists (
    select 1 from private.teacher_admins a where a.user_id = auth.uid()
  ) then
    raise exception 'permission denied: teacher access is restricted';
  end if;

  return query
  select l.id, u.email::text, l.action, l.details, l.created_at
  from private.teacher_audit_logs as l
  left join auth.users as u on u.id = l.actor_id
  order by l.created_at desc
  limit 100;
end;
$$;

revoke all on function public.is_teacher_admin() from public, anon;
revoke all on function public.teacher_log_event(text,jsonb) from public, anon;
revoke all on function public.teacher_dashboard_data() from public, anon;
revoke all on function public.teacher_audit_logs() from public, anon;

grant execute on function public.is_teacher_admin() to authenticated;
grant execute on function public.teacher_log_event(text,jsonb) to authenticated;
grant execute on function public.teacher_dashboard_data() to authenticated;
grant execute on function public.teacher_audit_logs() to authenticated;

comment on function public.is_teacher_admin() is 'Returns true only when auth.uid() exists in private.teacher_admins.';
comment on function public.teacher_dashboard_data() is 'Private student learning data; UUID allowlist enforced by auth.uid().';
comment on function public.teacher_audit_logs() is 'Private administrator audit log; UUID allowlist enforced by auth.uid().';
