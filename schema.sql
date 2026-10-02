create table if not exists files (
  id           uuid primary key default gen_random_uuid(),
  name         text not null,
  mime         text not null default 'application/octet-stream',
  size         bigint not null,
  storage_key  text not null unique,
  is_favorite  boolean not null default false,
  created_at   timestamptz not null default now()
);
create index if not exists files_created_idx on files (created_at desc);
