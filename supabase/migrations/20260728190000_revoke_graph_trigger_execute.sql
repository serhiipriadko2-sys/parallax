revoke execute on function public.prevent_graph_node_cross_owner_cascade()
  from public, anon, authenticated;

comment on function public.prevent_graph_node_cross_owner_cascade() is
  'Trigger-only guard for graph node deletes. Direct API execution is revoked from public client roles.';
