.. _rust_regex_backend:

==================
Rust Regex Backend
==================

Overview
========

This document proposes replacing Zeek's internal regular expression engine
with a Rust implementation.

For the staged implementation checklist that accompanies this design, see
:doc:`rust-regex-backend-plan`.
For a compatibility inventory of preserved behavior and cleanup candidates, see
:doc:`rust-regex-backend-compat`.

The primary goals are:

* use Rust for all current regex consumers in Zeek,
* make Rust a required part of Zeek's core build,
* keep the existing high-level C++ matcher API shape so that most call sites
  continue to work with minimal change, and
* remove Zeek's current ``RE``/``NFA``/``DFA``/``CCL`` regex runtime over time.

This is intentionally an aggressive integration point. Regex touches script
``pattern`` values, string builtins, ``table[pattern]`` lookups, signature
matching, serialization, and public matcher stats. If Zeek can successfully
swap this subsystem to Rust, it establishes a workable model for future
core Rust components.


Motivation
==========

This project is attractive for both technical and strategic reasons.

Technically, it replaces a complex custom regex implementation with a backend
that can build on the Rust regex ecosystem and Rust's safety guarantees.
Strategically, it introduces Rust as a first-class core dependency in a part of
Zeek that is central enough to matter, but still has a reasonably clear API
boundary.

Benefits include:

* less memory-unsafe code in a complicated parser/matcher subsystem,
* reuse of mature Rust regex building blocks instead of continued investment in
  custom automata internals,
* a concrete path for introducing Rust into Zeek's build, packaging, and CI,
  and
* a backend swap that can leave most higher-level Zeek code structurally
  unchanged.


Goals
=====

* Replace Zeek's regex runtime with a Rust backend for all current uses.
* Keep script-level ``pattern`` values and the general C++ matcher API intact.
* Preserve current call-site structure in places such as ``Expr.cc``,
  ``strings.bif``, ``Val.cc``, and ``RuleMatcher.cc`` whenever practical.
* Make ``rustc`` and ``cargo`` hard build dependencies.
* Keep pattern text available in C++ so equality, diagnostics, and Broker
  serialization can continue to use source text.
* Accept changes to internal metrics and debug information when a direct
  one-to-one mapping no longer makes sense.


Non-Goals
=========

* Preserving every DFA cache metric exactly as it exists today.
* Keeping the current ``NFA``/``DFA``/``CCL`` implementation around long term.
* Rewriting unrelated Zeek subsystems in Rust as part of this project.
* Promising perfect compatibility for every parser and matching corner case in
  the first implementation.


Current Zeek Surface Area
=========================

Today, regex support is split across three broad layers.

The first is the regex front-end in ``re-scan.l`` and ``re-parse.y``. This is
where Zeek-specific pattern syntax is tokenized and parsed.

The second is the runtime in ``RE.h``/``RE.cc`` and the supporting
``NFA``/``DFA``/``CCL`` implementation. This layer provides:

* exact, anywhere, and prefix matching,
* compile-set support for disjunctive matching used by ``table[pattern]`` and
  ``set[pattern]``,
* incremental matching through ``RE_Match_State``, and
* access to DFA-oriented cache and stats internals.

The third is the set of consumers that rely on the above API:

* ``Expr.cc`` for ``pattern`` operators and equality,
* ``strings.bif`` for string split and substitution helpers,
* ``Val.cc`` for ``table[pattern]`` and ``set[pattern]`` lookup,
* ``RuleMatcher.cc`` for signatures and file magic,
* ``broker/Data.cc`` for serialization, and
* ``zeek.bif`` and ``stats.bif`` for matcher stats.

This separation is what makes a backend swap realistic. Most Zeek code does not
care how a regex is implemented internally as long as the matcher API and data
contracts remain usable.


Proposed Architecture
=====================

C++ Facade
----------

The existing C++ types should remain the public integration boundary for the
rest of Zeek:

* ``RE_Matcher``
* ``detail::Specific_RE_Matcher``
* ``detail::RE_Match_State``

The implementation behind those types changes from Zeek-owned automata objects
to opaque Rust-owned handles.

The C++ side should continue to own:

* original pattern text,
* case-insensitive and single-line mode flags,
* constructors and destructors visible to the rest of Zeek, and
* any compatibility glue needed by current call sites.

The Rust side should own:

* compiled regex programs,
* compiled regex-set or multi-pattern programs,
* incremental streaming state, and
* any backend-specific caches.

This keeps most of Zeek above ``RE.h`` insulated from the implementation
change while still letting the old engine internals disappear.


Rust Workspace and FFI Boundary
-------------------------------

Zeek should add a top-level Rust workspace for core Rust code. The first crate
should be a regex backend, for example ``rust/zeek-regex``, built as a
``staticlib`` and linked into the main build.

The boundary between C++ and Rust should be a narrow C ABI:

* no direct exposure of Rust types to C++,
* no requirement for ``cxx``, ``autocxx``, or similar frameworks in the first
  iteration, and
* a checked-in C header that declares the exported functions Zeek uses.

This keeps the first integration simple, explicit, and portable. If the FFI
surface stabilizes later, generated headers can be revisited.


Runtime Model
-------------

The Rust backend should be byte-oriented and treat matching over arbitrary
network payloads as a first-class use case.

The C++ facade should pass pattern text, byte buffers, and mode flags to Rust.
Rust should return simple backend-neutral results such as:

* success or failure,
* match length or end offset,
* matched pattern ids for regex sets, and
* opaque streaming-state handles.

Two existing contracts are worth preserving because they reduce churn:

* ``CompileSet()`` should continue to associate non-zero accept ids with
  patterns. Existing C++ callers already rely on that numbering.
* ``RE_Match_State`` should continue to expose accepted matches as
  ``AcceptIdx -> MatchPos`` so that signature code does not need a large
  redesign.

Internally, the Rust crate may choose different matching strategies for
different operations. A single backend is not required for all use cases.
For example, exact and anywhere matches, regex-set matching, and incremental
signature scanning may reasonably use different internal automata or cache
layouts as long as the exposed C++ behavior remains acceptable.


Pattern Syntax Strategy
-----------------------

The recommended implementation path is staged.

Initially, Zeek should keep its current pattern front-end and swap the matcher
runtime behind it. This constrains the blast radius and makes it much easier to
hold the rest of Zeek stable while the Rust backend matures.

Longer term, Zeek can decide how much of the current regex syntax machinery
still earns its keep. There are two plausible end states:

* retain the current parser and compile its result to Rust forever, or
* simplify or replace parts of the parser once compatibility costs are better
  understood.

This project does not need to settle that question up front. A runtime swap is
already valuable, and it is the cleaner first milestone.


Build Integration
=================

Rust should become a required build dependency. At a minimum, Zeek's build
system will need to:

* detect ``rustc`` and ``cargo`` in ``configure`` and CMake,
* define a minimum supported Rust version,
* invoke Cargo from CMake without requiring an additional CMake-Rust bridge,
* support cross-compilation by forwarding the relevant target information,
* update CI for Linux, macOS, and Windows builds, and
* document Rust as a required dependency in the build instructions.

For release engineering and offline or reproducible builds, Zeek should vendor
crate dependencies as part of source packaging instead of relying on live
network access during builds. That keeps the Rust dependency manageable for
release tarballs and downstream packagers.


Compatibility Expectations
==========================

Stable Surfaces
---------------

The project should aim to keep the following surfaces stable:

* the script-level ``pattern`` type,
* the general ``RE_Matcher`` API shape used by most C++ callers,
* ``table[pattern]`` and ``set[pattern]`` lookup behavior at a high level,
* Broker serialization based on stored pattern text, and
* common string functions such as splitting and substitution.


Expected Differences
--------------------

Some changes are acceptable and should not block the migration:

* matcher metrics and cache statistics may change shape or meaning,
* DFA-specific debug and introspection output may disappear or become
  backend-neutral,
* some corner-case matching semantics may change if the Rust implementation
  cannot or should not preserve them exactly, and
* parser quirks may eventually be simplified if the cost of preserving them
  outweighs their value.

The key compatibility target is not bit-for-bit parity with the current engine.
It is preserving the overall Zeek programming model while changing the engine
underneath it.


Call Sites Needing Explicit Attention
=====================================

Most users of ``RE_Matcher`` should continue to work with small or no changes.
The main exceptions are places that reach below the general matcher API and
touch DFA-oriented internals directly.

These areas should be expected to need targeted adaptation:

* matcher stats exposed through ``zeek.bif`` and ``stats.bif``,
* ``TablePatternMatcher`` stats gathering in ``Val.cc``,
* signature stats gathering and any direct DFA access in ``RuleMatcher.cc``,
  and
* any code that expects ``Specific_RE_Matcher::DFA()`` or related types to be
  meaningful.

The design should treat raw DFA access as a legacy escape hatch to retire, not
as a stable compatibility promise.


Migration Plan
==============

Phase 0: Build and FFI Skeleton
-------------------------------

* Add Rust toolchain detection to ``configure`` and CMake.
* Introduce the Rust workspace and regex crate.
* Add a minimal C ABI and C++ wrapper layer.
* Wire the new crate into CI and source packaging.


Phase 1: Non-Streaming Matching
-------------------------------

* Implement exact, anywhere, and prefix matching behind
  ``Specific_RE_Matcher``.
* Route string helper functions through the Rust backend.
* Preserve stored pattern text and the high-level ``pattern`` API.

This phase proves out build integration, FFI, and most of the common
non-signature regex operations.


Phase 2: Regex Sets for ``table[pattern]`` and ``set[pattern]``
---------------------------------------------------------------

* Implement ``CompileSet()``, ``MatchSet()``, and ``MatchAll()`` for set-style
  matching.
* Preserve current accept-id numbering so ``TablePatternMatcher`` can remain
  structurally unchanged.
* Replace DFA-specific stats access with a backend-neutral story or accept
  metric changes where appropriate.


Phase 3: Incremental Matching for Signatures
--------------------------------------------

* Reimplement ``RE_Match_State`` on top of Rust-owned streaming state.
* Preserve the accepted-match data model used by ``RuleMatcher.cc``.
* Validate behavior across chunk boundaries, anchors, and repeated updates.

This is the highest-risk phase and should be treated as the real go or no-go
checkpoint for a full engine replacement.


Phase 4: Remove Legacy Engine Internals
---------------------------------------

* Delete the old regex runtime once the Rust backend covers all required uses.
* Remove or rewrite code that still depends on ``DFA``/``NFA``/``CCL`` details.
* Convert any remaining stats or debug APIs to backend-neutral forms where
  practical.


Phase 5: Revisit Parser Ownership
---------------------------------

* Evaluate whether ``re-scan.l`` and ``re-parse.y`` still provide enough value
  to keep.
* Preserve them if they remain the simplest way to maintain Zeek semantics.
* Simplify or replace them only after the runtime swap is complete and well
  tested.


Testing and Validation
======================

Existing Zeek tests already provide a strong regression base for much of this
work. In addition to keeping those passing, the Rust migration should add
targeted coverage for:

* exact, anywhere, and longest-prefix behavior,
* empty matches and anchor handling,
* ``table[pattern]`` multi-match behavior and result ordering,
* incremental matching across arbitrary chunk boundaries,
* Broker serialization round-trips for patterns, and
* build and test execution without network access to external crate registries.

During development, it is reasonable to keep a temporary build-time switch that
allows running the old and new backends side by side for differential testing.
That switch should be considered transitional and removed once the Rust backend
is ready to become the only implementation.


Risks and Open Questions
========================

The main technical risks are concentrated in a few areas:

* incremental signature matching and streaming state,
* subtle matching semantics such as longest-prefix and empty-match behavior,
* the cost of preserving Zeek-specific parser quirks if those are deemed
  important, and
* release engineering for vendored crates and cross-platform builds.

Open questions that the first prototype should answer include:

* Which internal Rust matching strategy is best for incremental signature use?
* How much current parser behavior is worth preserving once the backend swap is
  working?
* Do current matcher stats need a backend-neutral replacement, or can they
  simply change?
* What minimum Rust version is reasonable for Zeek's supported platforms?


Recommendation
==============

This project is ambitious, but it is a credible and worthwhile direction.

The recommended path is to be aggressive about introducing Rust into Zeek's
build and regex runtime while being conservative about the C++ facade used by
the rest of the system. If the ``RE_Matcher`` surface remains intact and the
old engine internals are treated as replaceable, most of Zeek can continue to
work while the implementation underneath it changes completely.
