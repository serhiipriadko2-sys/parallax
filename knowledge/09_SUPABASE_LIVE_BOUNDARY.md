# Supabase Live Boundary — Snapshot observed 2026-07-28

At the observation time, AgiIskra was active and included an `iskra-agent` Edge Function with JWT validation, origin restrictions, beta/quota controls, and an upstream Workspace Agent call. The separate `iskra-memory-gateway` was active in `probe_only`, returning a security hold for privileged routes.

Security advisors reported RLS enabled without policies on `iskra_memory` tables, plus additional GraphQL and `SECURITY DEFINER` exposure warnings. This is a dated snapshot, not a current guarantee.

PARALLAX Ω therefore ships no Supabase mutation and treats durable memory as unavailable until Git-backed migrations, grants, RLS, function ACLs, consent binding, replay protection, write/read-back, deletion, and live drift tests all pass.
