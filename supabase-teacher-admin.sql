-- 職業安全衛生乙級智慧互動學習系統：教師後台授權
-- 僅允許 ycc0824@gmail.com 透過已登入的 Supabase Auth 帳號讀取學生學習資料。
-- 請在 Supabase Dashboard > SQL Editor 以專案管理者身分執行一次。

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
  if auth.uid() is null
     or lower(coalesce(auth.jwt() ->> 'email', '')) <> 'ycc0824@gmail.com' then
    raise exception 'permission denied: teacher access is restricted';
  end if;

  return query
  select d.user_id, u.email::text, d.data, d.updated_at
  from public.oshb_learning_data as d
  left join auth.users as u on u.id = d.user_id
  order by d.updated_at desc nulls last;
end;
$$;

revoke all on function public.teacher_dashboard_data() from public;
revoke all on function public.teacher_dashboard_data() from anon;
grant execute on function public.teacher_dashboard_data() to authenticated;

comment on function public.teacher_dashboard_data()
is 'Private teacher dashboard data; only the allowlisted administrator email can execute.';
