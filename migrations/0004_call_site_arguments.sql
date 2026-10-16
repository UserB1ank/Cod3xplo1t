-- Codexploit P3 (part 1): call-site argument facts.
--
-- "GET was called" is not enough to find an attack surface: the route path, the
-- handler symbol and the SQL prefix live in the arguments. They are recorded on
-- the call site, as facts the SCG owns (design doc §3.1, implementation guide
-- §7.1), so every later rule reads them instead of re-parsing the source.
--
-- `args_json` holds the positional argument facts (string literals with their
-- unquoted value, other literals, symbol references with their resolution, and
-- plain expressions). `receiver_from` records the call a selector's receiver was
-- bound from — `r := gin.Default()` makes `r.GET(...)` a gin route — which is how
-- a rule can attribute a registration without type checking.

ALTER TABLE scg_call_sites ADD COLUMN args_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE scg_call_sites ADD COLUMN receiver_from TEXT NOT NULL DEFAULT '';
