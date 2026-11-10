# ZAM compilation caching — investigation findings

**Status:** working opt-in cache, draft for human review. Not for submission
as-is.
**Scope:** evaluate caching ZAM script-optimizer output between runs to speed
up the `-a zam` btest suite (and CI), which currently recompiles everything on
every process start.

**AI assistance:** this investigation, the instrumentation, and the cache
implementation were produced with AI assistance (Claude). A human contributor must
review the complete diff and this document before any submission, per
`AI_POLICY.md`.

## Using and exercising the work

Everything is opt-in; without it, `-O ZAM` and `-a zam` behave exactly as
before. User-facing documentation is in the "ZAM Body Cache" section of
`README.md` in this directory.

The cache itself:

- `-O cache-ZAM` (or `ZEEK_ZAM_CACHE=1`): enable the on-disk body cache; implies
  `-O ZAM` unless other ZAM generation options are given. Each serializable
  compiled body is stored as `zam-<config>-<key>.zbc`; later runs load matching
  entries instead of compiling. Concurrent processes may share a directory
  (writes are temp-file + atomic rename). The cache is bypassed in diagnostic
  modes (usage analysis, dumps, profiling).
- `ZEEK_ZAM_CACHE_DIR=<dir>`: the cache directory; defaults to
  `$XDG_CACHE_HOME/zeek/zam`, else `~/.cache/zeek/zam`. Created if needed; if it
  can't be, Zeek warns and compiles normally.

Diagnostics (these require ZAM to be active, `-O ZAM` or `ZEEK_ZAM=1`):

- `ZEEK_ZAM_TIMING=1`: per-phase wall-clock breakdown of optimization and
  compilation, including the cache's own key/load/deserialize work.
- `ZEEK_ZAM_CACHE_DEBUG=1` (with the cache enabled): per-outcome body counts and
  compile time (hit, stored, or the serializer gate that refused the body), the
  costliest uncached bodies, and each stored body's key and name.
- `ZEEK_ZAM_CACHE_KEYS=1`: print each function's effective key.
- `ZEEK_ZAM_CACHE_VERIFY=1`: round-trip self-verification. Every serializable
  body is serialized, deserialized, and the reconstruction installed in place of
  the original, so the btest baselines exercise reconstructed code.
  `ZEEK_ZAM_CACHE_VERIFY_LOG=<file>` additionally compares every field of each
  original body against its reconstruction and appends any non-equivalent
  difference to the file, independent of whether a test exercises it.

## Problem

The btest `zam` alternative (`testing/btest/btest.cfg` `[environment-zam]`)
sets `ZEEK_ZAM=1`, which is equivalent to `-O ZAM`. Every one of the ~1900
test processes re-runs the full script-optimization pipeline from scratch over
the base-script corpus it loads. CI runs three `-a zam` jobs
(`.github/workflows/check.yml`: plain, ASan, UBSan), each throttled to
`ZEEK_CI_BTEST_JOBS: 3` "due to OOM issues with ZAM tasks."

There is currently **no** persistence of compiled ZAM output. Vern Paxson's
original 2020 ZAM work included a `ZBody::SaveTo()` "ZAM disk format" (commit
`e6d5432924`), later removed (`b7dff3c067`, "factor out savefile stuff"). The
current code records the intent and the deferral in `ZAM/ZBody.h:45-55`:
"Older code exists for save files, but let's see if we can avoid having to
support them, as they're a fairly elaborate production."

## Measurements

Instrumentation: an env-gated (`ZEEK_ZAM_TIMING`) `ZAMPhaseTimer` was added to
`src/script_opt/ScriptOpt.{h,cc}` and `src/script_opt/ZAM/Driver.cc`, charging
wall-clock time to each pipeline phase and printing a summary at the end of
`analyze_scripts()`. Inert unless the variable is set.

### Per-process overhead is almost entirely the base-script corpus

Wall-clock, default script load, `event zeek_init(){}` (Apple silicon, Debug-ish build):

| scenario                | real   |
|-------------------------|--------|
| ZAM **off**, full base  | 0.68 s |
| ZAM **on**, full base   | 3.51 s |
| ZAM **on**, bare (`-b`) | 0.57 s |

ZAM adds **~2.8 s per process**, essentially 100% attributable to the base
corpus: bare mode adds ~0, and loading several extra protocol/policy scripts on
top of the default load added only 9 functions / ~0.03 s (1345 → 1354). Every
`-a zam` test pays the full ~2.8 s for the same base corpus.

Scale: ~1900 tests × ~2.8 s ≈ **~1.5 h of serial recompute per suite run**,
nearly all redundant, repeated across 3 CI jobs.

### Where the time goes (full base, ~2.56 s in-pipeline, 1345 functions ≈ 1.9 ms/func)

| phase                       | %     |
|-----------------------------|-------|
| reduce                      | 29.2% |
| optimize-AST                | 19.5% |
| usedefs + usedefs-remove    | 27.0% |
| zam-compile                 | 11.1% (of which low-level opt 4.9%) |
| inline                      |  4.4% |
| genid-defs                  |  4.0% |
| reprofile                   |  2.8% |
| profile (ProfileFuncs)      |  1.9% |
| reduce-check                |  ~0%  |

**AST-level optimization (reduce + optimize-AST + usedefs ≈ 76%) dominates; the
final ZAM bytecode emission is only ~11%.**

## Implications for a cache design

1. Caching only the ZAM-emit phase is not worth much (~11%). The expensive work
   is upstream AST optimization. The only large lever is caching the
   **fully-optimized body** — i.e. serialize the final `ZBody` so a cache hit
   skips reduce/optimize-AST/usedefs/compile entirely. That reclaims nearly the
   whole ~2.8 s for unchanged scripts.
2. The change-detection key already exists and is already computed on the ZAM
   path: `ProfileFunc::HashVal()` / `ComputeProfileHash()`
   (`src/script_opt/ProfileFunc.{h,cc}`). The `-O gen-C++` backend already uses
   it as a cross-run cache key (`compiled_scripts[hash]` →
   `func->ReplaceBody()` in `ScriptOpt.cc::use_CPP`).
3. **Inlining caveat (correctness-critical):** `ProfileFuncs` (and every
   `HashVal()`) is computed *before* inlining (`ScriptOpt.cc`: `pfs` built, then
   the `Inliner` runs). ZAM inlines aggressively and coalesces event-handler
   bodies, so a compiled body depends on its inlined callees. A per-body cache
   key must therefore fold in the transitive closure of inlined callees' hashes
   (or key on the post-inline reduced body), not the pre-inline `HashVal()`
   alone. The cache key must also incorporate the Zeek build identity (opcode
   numbering can change) and the active analysis options (`keep-asserts`,
   `no-inline`, `no-ZAM-opt`, …).
4. The hard, missing piece is serialization/deserialization of `ZBody`/`ZInst`.
   A `ZInst` holds live process-interned references: `TypePtr t, t2`, a `ZVal`
   constant, and a `ZInstAux*` (type/constant arrays, iteration info,
   global/lambda/event references). The CPP backend's `InitsInfo`/`RuntimeInits`
   machinery already knows how to reconstruct types, constants, and attributes
   from a compact form and is the natural thing to borrow rather than reviving
   the old text format.

## Security note (per `SECURITY_MODEL.md`)

An on-disk cache that reloads input-derived compiled state is a deserialization
and trust-boundary surface (cache poisoning, stale-across-version loads). A real
implementation needs: a cache keyed/validated by build identity + options,
rejection of malformed/truncated/mismatched files, and adverse-case tests. The
cache should be treated as untrusted on read. (The measurement work above does
not touch this.)

## Cacheability analysis (sizing the serializer)

Before building the full serializer, a temporary env-gated analyzer was used to
size the work. For a real `-O ZAM` run it inspected every compiled body's
instruction stream and recorded which features a serializer would have to
handle, with a histogram of blockers, and could mark features as "assumed
handled" so coverage could be measured as serializer capability grew. It is not
part of this branch: `ZEEK_ZAM_CACHE_DEBUG` now reports the actual serializer
gate that refuses each body, along with its compile cost.

Scope note: the analyzer assessed the instruction stream (ops, operands,
per-instruction types, constants, and `ZInstAux` contents). Body-level
structures (switch case-maps, globals, frame layout) are not yet assessed;
those are bounded and largely by-name/atomic, but must be covered by the real
serializer.

### Blocker histogram (full base corpus, 1345 bodies, 56 973 instructions)

Top blockers by fraction of bodies they block:

| blocker            | bodies blocked | notes |
|--------------------|----------------|-------|
| aux:call-expr      | 79.1% | `CallExpr` on call insts — backtrace + trigger-lookup key |
| aux:id-val         | 77.8% | `IDPtr` for function-name access — by-name |
| type:record        | 76.2% | record types — needs type reconstruction |
| aux:direct-func    | 57.9% | `Func*` for direct calls — by-name |
| type:table         | 54.5% | table types |
| type/const:enum    | 42.5% / 34.5% | enum types/consts — by-name |
| type:func          | 26.6% | function types |
| type:vector/any    | 18.6% / 13.5% | |
| aux:event-handler  | 10.8% | `EventHandler*` — by-name |
| aux:field-inits    | 9.3% | record constructors |
| aux:cat-args/attrs | 5.9% / 0.1% | |
| aux:lambda         | 1.9% | lambda construction (AST) |
| aux:when-info      | 0.7% | `when` statements (AST) |

### Coverage curve (cumulative serializer capability)

| tier | capability added | bodies cacheable | instructions clean |
|------|------------------|------------------|--------------------|
| A | atomic scalars only (baseline) | 1.9% | 40.0% |
| B | + type/const reconstruction (all types) | 11.4% | 83.5% |
| C | + by-name refs (id-val, direct-func, event-handler) | 19.0% | 89.7% |
| D | + call-expr | **84.2%** | 99.3% |
| E | + record constructors (field-inits, attrs, cat-args) | **98.1%** | 99.9% |
| F | everything except lambda + when-info | 98.1% | 99.9% |
| G | everything | 100% | 100% |

### Readout

- **Type reconstruction is the mandatory foundation** (A→B: instructions
  40%→83.5%). This is exactly what the CPP backend's `InitsInfo`/`RuntimeInits`
  already does and should be borrowed rather than reinvented.
- **`aux:call-expr` is the single highest-leverage item** (C→D: bodies
  19%→84%). It is not cosmetic: `OPs/calls.op` uses it both as the frame's
  current-call for backtraces (`SetCall`) and as a trigger-lookup key
  (`trigger->Lookup`). But it is bounded, reconstructible AST + a location, not
  a fundamental blocker. The pointer-identity-as-trigger-key use (only in
  `when`/trigger contexts, which are themselves rare) is the subtlety to handle.
- **Record constructors** (field-inits/attrs/cat-args) take coverage to 98.1%.
- **`lambda` + `when-info` are the entire remaining 1.9%** and are the
  genuinely hard AST cases. A serializer can simply fall back to normal
  compilation for those bodies and still cache ~98% — so they need not be in
  the first implementation.

### Serializer roadmap (priority order)

1. Type + constant (de)serialization — reuse CPP `InitsInfo` machinery. *(req.)*
2. By-name rebinding of `id_val`, `func`, `event_handler` against the running
   global/event registries.
3. A compact `call_expr` representation (location + call identity; full fidelity
   only where trigger/`when` semantics require it).
4. Record-constructor aux (`field_inits`, `attrs`, `cat_args`) and the aux
   type/map vectors.
5. Body-level structures: frame layout/denizens, globals, switch case-maps.
6. Fall back to normal compilation for bodies containing lambdas or `when`
   (≈1.9%); add later if worthwhile.

Expected coverage after steps 1–4: ~98% of bodies, which at ~2.8 s/process over
the base corpus is essentially the whole win.

## Effective cache key (validated)

A per-body cache must share the base corpus across tests (each test's *total*
program differs, so a whole-program key would never hit). The key must also be
inlining-safe: `ComputeProfileHash()` folds in identifier names/types/constants
but not called-function bodies, so a bare `HashVal()` is unsafe when inlining is
on.

`effective_cache_key(pf, pfs)` (in `ScriptOpt.cc`) = `pf->HashVal()` merged with
the `HashVal()` of every script function transitively reachable through the call
graph, combined over a sorted set (order-independent, cycle-safe). Inlined
callees ⊆ called functions, so this is a safe over-approximation (a changed
non-inlined callee only causes a conservative miss, never a wrong hit). The
file-level key additionally folds in build identity + analysis options.

Validated via the `ZEEK_ZAM_CACHE_KEYS` diagnostic:
- Deterministic across runs: 918 non-lambda base functions produced identical
  keys run-to-run (0 diffs); lambda key-hashes were an identical multiset (only
  lambda *display names* are nondeterministic, and lambdas fall back to normal
  compilation).
- Stable under test-specific additions: adding a function that calls into the
  base corpus changed **0** base-function keys — so base bodies hit the cache
  regardless of which test loads them.

**Later finding: source hashes are not enough.** A compiled body also depends
on the environment it was compiled in, which differs between test processes
loading different scripts. Sharing a cache directory across tests produced
*silent* divergence (e.g. `core.tunnels.*` losing `Tunnel::CLOSE` log lines),
because the profile type-hash covers only a record's *original* fields while
ZAM hardwires field offsets, redef-extensible enums get load-order-dependent
values, folded `const` values are keyed by name only, and source locations
(visible in error messages) aren't hashed at all. The key now also folds in a
**compile-environment fingerprint** for the body and every transitive callee:
full type structure (all fields including redef additions, attributes, enum
name/value maps, unspecified-vector flag), referenced global-constant values
(hashed structurally, since table iteration order depends on the per-process
hash seed), and every statement/expression location. Attribute expressions
involving lambdas are hashed by location and type: rendering them embeds
randomized lambda names and, once compiled, compiled code, which made ~100
keys differ between runs until fixed. Coalesced event handlers are keyed on
their constituent bodies' keys in execution order. Keys are identical across
cold runs without a fixed hash seed.

## Serialization architecture (decided, from substrate survey)

Zeek has no general `Type` serializer, but two facts make the ZAM cache
tractable without reconstructing types from scratch:

- The cache is loaded **after** the (identical) scripts are parsed, so every
  `Type`/named `ID`/`Func`/`EventHandler` an instruction references **already
  exists** in the loading process.
- `ProfileFuncs` already computes a stable, content-derived hash for every type
  (`HashType`) and keeps a hash → representative-`Type*` map (`type_hash_reps`,
  now exposed as `TypeForHash`).

Resulting codec decisions:

- **Types:** serialize as the profile **type-hash**; at load resolve via
  `ProfileFuncs::TypeForHash(h)` against the current process. Uniform for named
  and anonymous/compound types; no structural rebuild. A type not present in
  the map at store time makes that body non-cacheable (gated out).
- **Atomic constants:** serialize by value and rebuild via `val_mgr` /
  `make_intrusive<…>` (addr/subnet via string ctor, port via packed uint, enum
  via its type-hash + int). Container constants gated out initially (rare as
  instruction constants).
- **By-name references** (`aux.id_val`, `aux.func`, `aux.event_handler`):
  serialize the name; resolve via `lookup_ID` / `zeek::id::find_func` /
  `event_registry` at load.
- **Validation / key:** follow house style (hash-stamping, not a magic number).
  The file-level key folds each body's `effective_cache_key` plus build identity
  (`zeek_version()` + a format-version constant + the executable's mtime) and an
  analysis-options hash. Any mismatch ⇒ whole-file miss ⇒ normal compilation.
- **Capability gate (correctness invariant):** a body is cached only if every
  instruction is fully serializable under the implemented capability; otherwise
  it is compiled normally. The cache can therefore never cause an incorrect
  execution — at worst a miss. `lambda`/`when` bodies always fall back.

Reused from CPP where applicable: the name→Type/ID resolvers
(`get_record_type__CPP`-style via `global_scope()->Find`), and the
reconstruction *logic* patterns in `RuntimeInits.cc` (not the C++-emission half).

## Implementation status

Implemented on branch `topic/timw/zam-caching-investigation` (see the commit
series for detail):

- `ZAMBodyCache` / `ZBodySerializer` (`src/script_opt/ZAM/BodyCache.{h,cc}`):
  per-body serialization of compiled ZAM, an on-disk store keyed as above,
  and load/install that skips compilation on a hit. A hit also restores the
  side effects compilation would have had (interpreter frame size; one-time
  ZAM runtime init); bodies whose compilation emitted any diagnostic are never
  stored, since a hit would silently drop that output.
- Serialized: instructions and operands; types (by profile type-hash, resolved
  to the live representative, with a strict failure on mismatch); atomic
  constants, including constants that optimized built-ins keep in an
  instruction's constant slot; frame layout; globals (resolved in the global
  scope, never via the scope stack); loop iterators; switch case maps; and
  aux data: elems, maps, types, flags, control-flow info, `cat()` args
  (rebuilt), by-name function/event/ID refs, call expressions (a bounded AST),
  and record field initializers (re-linked to the type's own).
- Still not cached, by serializer gate: bodies with lambdas or `when`, call
  expressions outside the supported shape, non-atomic constants, and a few
  bodies whose types hit the `vector of any` / `vector()` hash ambiguity
  (deliberate misses).

## Results

Default script corpus (`zeek -e 'event zeek_init(){}'`, debug+ASan build on
Apple silicon, median of 3):

| configuration | wall time |
|---|---|
| ZAM off | 0.65 s |
| ZAM, no cache | 3.60 s |
| ZAM, warm cache | **1.49 s** |

On a warm run 1254 of 1345 compiled bodies (~93%) load from the cache; ZAM's
own per-process overhead drops from ~2.95 s to ~0.85 s (-71%). What remains is
mostly the fixed `inline` and `profile` passes, the cache's own
load/deserialize/key work (~0.2 s), and the 91 bodies still compiled (~0.37 s,
chiefly call-expression shapes outside the supported set).

Validation, at every increment: round-trip verification over `language/` and
`core/` under `-a zam` (453/453, 284/284) with zero structural differences;
and two passes of both suites over a *single shared* cache directory, so that
bodies compiled under one test's scripts are offered to every other test
(453/453 and 284/284 on both passes).

Not yet measured: the end-to-end wall-clock effect on a full `-a zam` suite
run or in CI. Per-test savings should approach the per-process figure above
for tests that load the default scripts; bare-mode (`-b`) tests spend little
time in ZAM to begin with.

## Lessons from validation

The btest baselines alone were not a sufficient oracle. Several reconstruction
bugs passed every suite and were found only by the structural comparison
(`ZEEK_ZAM_CACHE_VERIFY_LOG`) or by sharing one cache across suites:

- Instructions rebuilt via `ZInstI(op, op_type)`, which resolves to the
  `ZInstI(ZOp, int v1)` constructor and set every `op_type` to `OP_V`.
- Constants dropped from the constant slot of optimized built-ins whose
  `op_type` doesn't mark a constant (this silently disabled file analysis in
  `core.tcp.large-file-reassembly` under verification).
- By-name globals resolved through the scope stack, binding to same-named
  locals.
- `vector of any` and the unspecified `vector()` sharing a profile hash.
- Lost parenthesization in reconstructed call expressions.
- The cross-process key gaps described under "Effective cache key".

Any further serializer work should keep both checks in its loop.

## Remaining work

- **Productization.** `BuildId` is the version string plus a format version,
  which does not change between local rebuilds of the same version; before
  default-on use it needs a real binary fingerprint (executable hash or
  mtime+size). No cache eviction or size management exists. Decide how the
  btest `zam` alternative and CI would enable the cache (e.g. `ZEEK_ZAM_CACHE=1`
  and a per-run `ZEEK_ZAM_CACHE_DIR` in `btest.cfg`).
- **Security** (per `SECURITY_MODEL.md`). The cache directory is a
  deserialization boundary. Loads validate headers, bound sizes, and fail
  closed on malformed or unresolvable data, but there is no integrity
  protection against a writer who can modify cache files. Adverse-case tests
  (truncated, corrupted, and mismatched-header files) still need to be added as
  btests.
- **Regression tests.** `opt/cache-ZAM.zeek` covers enabling the cache, cold/warm
  equivalence, and an unusable cache directory. Configuration separation and
  diagnostics-mode bypass still need focused btests, in addition to the
  suite-wide verification used during development.
- **Coverage.** The remaining ~6% of bodies (lambdas, `when`, other
  call-expression shapes) and the fixed per-process passes (`inline`,
  `profile`) are now the main costs; skipping those passes on an all-hit run
  would need care, since inlining decisions also determine which bodies exist.
