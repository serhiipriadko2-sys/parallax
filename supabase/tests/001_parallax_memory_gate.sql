do $test$
declare
  expected_tables text[] := array[
    'gateway_events','horizon_events','memory_archive','memory_consent_registry',
    'memory_dream_seeds','memory_edges','memory_journal','memory_open_loops',
    'memory_sense_events','memory_shadow','statecycle_snapshots'
  ];
  table_name text;
  policy_name text;
  bad_count integer;
begin
  foreach table_name in array expected_tables loop
    if not exists (
      select 1 from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'iskra_memory'
        and c.relname = table_name
        and c.relrowsecurity
    ) then
      raise exception 'PARALLAX memory gate: missing RLS table %', table_name;
    end if;

    policy_name := table_name || '_deny_clients';
    if not exists (
      select 1 from pg_policies
      where schemaname = 'iskra_memory'
        and tablename = table_name
        and policyname = policy_name
        and roles @> array['anon'::name, 'authenticated'::name]
    ) then
      raise exception 'PARALLAX memory gate: missing client deny policy on %', table_name;
    end if;
  end loop;

  select count(*) into bad_count
  from information_schema.role_table_grants
  where table_schema = 'iskra_memory'
    and grantee in ('anon', 'authenticated');
  if bad_count <> 0 then
    raise exception 'PARALLAX memory gate: client grants remain: %', bad_count;
  end if;

  if not exists (
    select 1
    from pg_constraint con
    join pg_class rel on rel.oid = con.conrelid
    join pg_namespace nsp on nsp.oid = rel.relnamespace
    join pg_attribute att on att.attrelid = rel.oid and att.attnum = any(con.conkey)
    where nsp.nspname = 'iskra_memory'
      and rel.relname = 'memory_consent_registry'
      and con.contype = 'p'
      and att.attname = 'consent_id'
  ) then
    raise exception 'PARALLAX memory gate: consent_id primary key missing';
  end if;

  if has_function_privilege('anon', 'public.prevent_graph_node_cross_owner_cascade()', 'EXECUTE')
     or has_function_privilege('authenticated', 'public.prevent_graph_node_cross_owner_cascade()', 'EXECUTE') then
    raise exception 'PARALLAX memory gate: trigger function remains client executable';
  end if;
end
$test$;
