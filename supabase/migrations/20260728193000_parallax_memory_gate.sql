revoke all on schema iskra_memory from public, anon, authenticated;
grant usage on schema iskra_memory to service_role;

do $gate$
declare
  table_name text;
  policy_name text;
begin
  foreach table_name in array array[
    'gateway_events',
    'horizon_events',
    'memory_archive',
    'memory_dream_seeds',
    'memory_edges',
    'memory_journal',
    'memory_open_loops',
    'memory_sense_events',
    'memory_shadow',
    'statecycle_snapshots'
  ] loop
    execute format('alter table iskra_memory.%I enable row level security', table_name);
    execute format('revoke all on table iskra_memory.%I from public, anon, authenticated', table_name);
    policy_name := table_name || '_deny_clients';
    if not exists (
      select 1
      from pg_policies
      where schemaname = 'iskra_memory'
        and tablename = table_name
        and policyname = policy_name
    ) then
      execute format(
        'create policy %I on iskra_memory.%I for all to anon, authenticated using (false) with check (false)',
        policy_name,
        table_name
      );
    end if;
  end loop;
end
$gate$;

create table if not exists iskra_memory.memory_consent_registry (
  consent_id text primary key,
  candidate_fingerprint text not null,
  expires_at timestamptz not null,
  state text not null default 'reserved'
    check (state in ('reserved', 'committed', 'quarantined')),
  record_id text unique,
  quarantine_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table iskra_memory.memory_consent_registry enable row level security;
revoke all on table iskra_memory.memory_consent_registry from public, anon, authenticated;
grant select, insert, update on table iskra_memory.memory_consent_registry to service_role;

do $policy$
begin
  if not exists (
    select 1
    from pg_policies
    where schemaname = 'iskra_memory'
      and tablename = 'memory_consent_registry'
      and policyname = 'memory_consent_registry_deny_clients'
  ) then
    create policy memory_consent_registry_deny_clients
      on iskra_memory.memory_consent_registry
      for all to anon, authenticated
      using (false)
      with check (false);
  end if;
end
$policy$;

comment on table iskra_memory.memory_consent_registry is
  'PARALLAX durable one-time consent and idempotency registry. Client roles are denied; service_role only.';
comment on column iskra_memory.memory_consent_registry.consent_id is
  'Unique host-issued consent identifier; primary idempotency key.';
