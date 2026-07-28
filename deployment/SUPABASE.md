# Supabase adapter gate

No migration or function is included. The observed live system had unresolved policy and exposure boundaries, and that snapshot may have changed.

Before enabling a memory adapter:

1. refresh live schema, grants, policies, advisors, function ACLs, and Edge Function versions;
2. create a Git-backed migration on a development branch;
3. pair least-privilege grants with per-identity RLS policies;
4. keep elevated keys only in backend components and never in model context;
5. implement trusted candidate-bound, expiring, one-time consent;
6. prevent direct Archive writes and enforce promotion gates in the database;
7. implement write + read-back hash + receipt as a bounded transaction or compensating workflow;
8. implement inspect, export, correct, delete, freeze, and deletion verification;
9. test anon, authenticated, service, cross-user, replay, and rollback boundaries;
10. merge, deploy, and re-read live state before claiming alignment.
