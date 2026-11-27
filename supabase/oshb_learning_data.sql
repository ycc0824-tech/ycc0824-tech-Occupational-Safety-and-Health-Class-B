-- 職業安全衛生乙級個人化學習系統：Supabase 雲端學習資料表
-- 在 Supabase Dashboard > SQL Editor 執行本檔。

create table if not exists public.oshb_learning_data (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.oshb_learning_data enable row level security;

grant usage on schema public to authenticated;
grant select, insert, update on table public.oshb_learning_data to authenticated;

drop policy if exists "Users can read own learning data" on public.oshb_learning_data;
create policy "Users can read own learning data"
  on public.oshb_learning_data
  for select
  to authenticated
  using (auth.uid() = user_id);

drop policy if exists "Users can insert own learning data" on public.oshb_learning_data;
create policy "Users can insert own learning data"
  on public.oshb_learning_data
  for insert
  to authenticated
  with check (auth.uid() = user_id);

drop policy if exists "Users can update own learning data" on public.oshb_learning_data;
create policy "Users can update own learning data"
  on public.oshb_learning_data
  for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

notify pgrst, 'reload schema';
