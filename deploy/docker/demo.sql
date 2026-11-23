-- Таблицы для пробы: compose кладёт их в базу shop при первом запуске базы.
-- Своя база — свои таблицы в "tables" настроек сборщика (./state/collector/collector.json).
create table accounts (
  id int primary key, owner text not null, balance numeric(14,2) not null,
  note text, updated_at timestamptz not null default now());
create table orders (
  id bigint primary key, account_id int not null references accounts(id),
  item text not null, paid boolean not null default false);
insert into accounts (id, owner, balance, note)
  select g, 'client-' || g, 1000 + g, 'note ' || g from generate_series(1, 100) g;
insert into orders select g, 1 + g % 100, 'item ' || g, g % 2 = 0 from generate_series(1, 50) g;
-- Роли агента и сервера не должны заводить свои объекты (-setup-sql это проверяет).
revoke create on schema public from public;
