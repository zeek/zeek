.. _rust_regex_backend_plan:

======================================
Rust Regex Backend Implementation Plan
======================================

This document is a companion to :doc:`rust-regex-backend`. The architecture
document explains the intended shape of the Rust regex backend. This document
turns that direction into a staged implementation plan.

The emphasis here is on what should be done first, where the work is likely to
land in the tree, and what evidence Zeek should require before moving to the
next phase.


Planning Principles
===================

The implementation should follow a few simple rules:

* keep the existing ``RE_Matcher`` facade stable for as long as possible,
* keep the C++/Rust FFI surface small and explicit,
* make early phases concrete and testable,
* treat incremental signature matching as a prototype-driven milestone instead
  of a fully-known implementation task, and
* avoid keeping the legacy engine and the Rust backend in permanent parallel.

That last point matters. A short-lived differential-testing path is useful, but
the project should still be planned as a real replacement, not as a long-term
dual-engine maintenance burden.


Milestones
==========

The recommended milestones are:

* ``M0``: Build integration and Rust workspace skeleton
* ``M1``: Non-streaming matcher replacement
* ``M2``: Regex-set support for ``table[pattern]`` and ``set[pattern]``
* ``M3``: Incremental/signature prototype and go or no-go decision
* ``M4``: Full cutover and legacy engine removal

``M0`` through ``M2`` should be planned in detail now.
``M3`` should be framed as a prototype milestone with clear evaluation
criteria rather than a rigid task list.


M0: Build Integration and Skeleton
==================================

Objective
---------

Make Rust a first-class required build dependency and land the minimal FFI
scaffolding needed to call a Rust regex backend from C++.


Concrete Deliverables
---------------------

* A top-level Rust workspace exists in the Zeek tree.
* A first Rust crate for regex support builds as a ``staticlib``.
* CMake can invoke Cargo and link the produced library into Zeek.
* ``configure`` rejects builds when Rust tooling is unavailable or too old.
* CI installs and uses the Rust toolchain on supported platforms.
* Source packaging includes vendored crate dependencies.


Likely File Touch Points
------------------------

Existing files:

* ``configure``
* ``CMakeLists.txt``
* ``doc/building-from-source.rst``
* ``ci/windows/build.cmd``

New files and directories:

* ``rust/Cargo.toml``
* ``rust/Cargo.lock``
* ``rust/zeek-regex/Cargo.toml``
* ``rust/zeek-regex/src/lib.rs``
* ``src/zeek/RegexBackend.h`` or a similar checked-in C ABI header


Checklist
---------

* Add Rust toolchain detection to ``configure``.
* Define a minimum supported Rust version.
* Add Cargo invocation and library linkage in ``CMakeLists.txt``.
* Decide where Cargo build artifacts live relative to Zeek's build tree.
* Add a minimal Rust library exporting a smoke-test function through a C ABI.
* Add a matching C++ wrapper that calls the smoke-test function.
* Update build documentation to list Rust as a required dependency.
* Update CI jobs to install Rust before configuring Zeek.
* Choose and document the vendoring strategy for crates in source tarballs.


Exit Criteria
-------------

``M0`` is complete when:

* a normal Zeek build fails early and clearly without Rust,
* a normal Zeek build succeeds with Rust on at least the main supported
  platforms in CI, and
* the main Zeek target links against the Rust static library through the new
  C ABI layer.


M1: Non-Streaming Matcher Replacement
=====================================

Objective
---------

Replace the non-streaming ``RE_Matcher`` operations with Rust while preserving
the current C++ API shape used by most of Zeek.


Scope
-----

This milestone covers:

* exact matching,
* anywhere matching,
* longest-prefix matching,
* stored pattern text and constructor behavior,
* string helpers in ``strings.bif``, and
* basic ``pattern`` operations that do not require regex-set or streaming
  support.

This milestone does not yet include ``CompileSet()`` or ``RE_Match_State``.


Likely File Touch Points
------------------------

Existing files:

* ``src/RE.h``
* ``src/RE.cc``
* ``src/Expr.cc``
* ``src/strings.bif``
* ``src/broker/Data.cc``

New or expanded Rust files:

* ``rust/zeek-regex/src/lib.rs``
* additional Rust modules for compile and match operations


Checklist
---------

* Introduce opaque Rust handles for compiled exact and anywhere matchers.
* Preserve ``PatternText()``, ``AnywherePatternText()``, and ``OrigText()``
  storage on the C++ side.
* Reimplement ``Compile()`` behind ``Specific_RE_Matcher`` using the Rust
  backend.
* Reimplement ``MatchAll()``, ``Match()``, and ``LongestMatch()`` for
  non-streaming calls.
* Keep empty-match handling compatible enough for existing string helpers.
* Update ``strings.bif`` consumers to rely only on the stable facade behavior.
* Keep Broker serialization based on pattern text rather than backend-specific
  compiled state.
* Add a temporary internal switch, if needed, for side-by-side comparison of
  old and new results during development.


Tests and Validation
--------------------

At minimum, validate:

* common ``pattern`` language tests,
* string splitting and substitution behavior,
* exact versus anywhere match differences,
* longest-prefix behavior for anchored and unanchored patterns, and
* empty-match behavior so callers do not accidentally loop forever.


Exit Criteria
-------------

``M1`` is complete when:

* the primary non-streaming regex APIs in ``RE_Matcher`` are backed by Rust,
* string helper behavior is good enough to keep existing tests passing or to
  justify deliberate compatibility adjustments, and
* the rest of Zeek no longer depends on legacy ``NFA``/``DFA`` internals for
  non-streaming operations.


M2: Regex Sets for ``table[pattern]`` and ``set[pattern]``
==========================================================

Objective
---------

Restore multi-pattern set compilation and matching so ``table[pattern]`` and
``set[pattern]`` continue to work through the same high-level C++ API.


Likely File Touch Points
------------------------

Existing files:

* ``src/RE.h``
* ``src/RE.cc``
* ``src/Val.cc``
* ``src/zeek.bif``

Rust backend files:

* ``rust/zeek-regex/src/lib.rs``
* set-matching support modules


Checklist
---------

* Implement Rust-backed compile-set support for exact multi-pattern matching.
* Preserve non-zero accept-id numbering used by ``TablePatternMatcher``.
* Reimplement ``CompileSet()``, ``MatchSet()``, and ``MatchAll()`` on the C++
  facade.
* Update ``TablePatternMatcher`` only where it depends on legacy DFA stats.
* Decide whether to keep a reduced stats API, a backend-neutral replacement,
  or a minimal compatibility shim.
* Add or update tests for multiple matching patterns and result ordering.


Exit Criteria
-------------

``M2`` is complete when:

* ``table[pattern]`` lookup works through the Rust backend,
* multi-match results preserve the required Zeek-facing behavior, and
* the only remaining regex functionality blocked on the legacy engine is
  incremental signature matching and any intentionally deferred parser work.


M3: Incremental Matching Prototype
==================================

Objective
---------

Answer the hard questions around ``RE_Match_State`` and signature matching
before committing to the full cutover.


Why This Phase Is Different
---------------------------

This is not just another checklist milestone. It is the part of the migration
most likely to reshape the backend design.

Zeek's current signature path depends on incremental matching state, accepted
match tracking, and behavior across arbitrary chunk boundaries. That is where
the old engine's lazy DFA design is most deeply embedded.


Prototype Questions
-------------------

The first prototype should answer at least these questions:

* Can ``RE_Match_State`` be reimplemented cleanly enough to preserve the
  current accepted-match model?
* Which internal Rust strategy is the best fit for incremental scanning?
* How much state must be kept per matcher versus per stream?
* Are current file-magic and signature tests good enough to validate chunked
  matching semantics, or do they need new focused tests?
* Are any user-visible semantic changes significant enough to justify pausing
  the replacement?


Prototype Scope
---------------

* Reimplement a Rust-backed ``RE_Match_State`` for a limited set of signature
  use cases.
* Exercise file magic and at least one representative payload signature path.
* Validate accepted matches, chunk-boundary behavior, and repeated ``Match()``
  calls with and without reset.


Go or No-Go Gate
----------------

Do not commit to removing the old engine until the prototype shows that:

* the incremental API can be preserved or acceptably adapted,
* signature behavior is good enough for Zeek's existing usage,
* the implementation complexity is still reasonable for long-term ownership,
  and
* performance and memory behavior are not obviously disqualifying.

If the prototype fails this gate, Zeek should reassess one of two things:

* narrowing the scope of the Rust regex replacement, or
* changing the C++ streaming API instead of trying to preserve it exactly.


M4: Full Cutover and Cleanup
============================

Objective
---------

Finish the swap and remove the legacy regex engine.


Checklist
---------

* Move the Rust backend from optional development path to sole implementation.
* Remove the old ``RE``/``NFA``/``DFA``/``CCL`` runtime once all required uses
  are covered.
* Rewrite or remove any code that still depends on raw DFA internals.
* Simplify public matcher stats if the old DFA-shaped model no longer fits.
* Remove temporary differential-testing switches.
* Revisit parser ownership only after the runtime cutover is stable.


Recommended Order of Work
=========================

The project should not begin with signatures.

The recommended order is:

#. land ``M0`` and prove the build integration works,
#. land ``M1`` and get everyday regex operations onto Rust,
#. land ``M2`` and restore ``table[pattern]``/``set[pattern]``,
#. run the ``M3`` prototype and decide whether to proceed unchanged, and
#. finish ``M4`` only after the prototype gate is satisfied.

This order creates real progress early, keeps most work on the stable
``RE_Matcher`` facade, and delays the riskiest implementation questions until
Zeek already has a working Rust foothold in core.


Immediate Next Tasks
====================

The first practical coding tasks should be:

* create the Rust workspace and regex crate,
* add Rust detection and version checks to ``configure`` and CMake,
* define the first C ABI header and one smoke-test symbol,
* link the Rust static library into the main build, and
* add a tiny C++ wrapper call to prove the boundary works end to end.

Only after that should the implementation move on to replacing
``Specific_RE_Matcher::Compile()`` and the first non-streaming match path.
