============================
Rust Regex Backend Direction
============================

This note outlines a direction for evolving Zeek's Rust regex backend. The
goal is not to immediately redesign the public C++ API around
``RE_Matcher``, but to make the backend easier to reason about, safer at the
FFI boundary, and a better home for Zeek-specific regex compatibility logic.

Motivation
==========

Zeek's legacy regex engine has already been removed, but the remaining code is
still split across two different implementation styles:

* ``src/RE.cc`` still owns Zeek-specific regex compatibility logic, pattern
  reconstruction, matcher lifecycle, and some historical compatibility
  behavior.
* ``rust/zeek-regex-backend/src/lib.rs`` owns the actual backend matching
  engine, but currently mixes safe Rust logic with FFI entry points, raw
  pointer conversion, and tests in a single file.

This split leaves the system with an awkward boundary. The heavy regex engine
work is in Rust, but much of the frontend translation and compatibility logic
remains in C++. At the same time, the Rust crate currently presents a larger
``unsafe`` and panic surface than desirable for an FFI-facing subsystem.

Goals
=====

The backend should evolve toward the following design principles:

* Keep the regex core and Zeek compatibility logic in safe Rust.
* Keep the FFI boundary as small as possible.
* Ensure FFI-reachable code does not panic.
* Preserve the existing C++ ``RE_Matcher`` API during the first migration
  steps.
* Keep Zeek's current pattern text, serialization, and reconstruction
  behavior stable unless explicitly changed.

Non-Goals
=========

This direction does not propose the following as an initial step:

* Replacing ``RE_Matcher`` with a Rust-native public API.
* Changing broker serialization formats for pattern values.
* Changing the meaning of ``PatternText()``, ``AnywherePatternText()``, or
  ``RustPatternText()``.
* Broad Rust migration outside the regex subsystem.

Current Layout
==============

C++
---

``src/RE.cc`` currently owns several distinct responsibilities:

* normalization of Zeek regex syntax onto Rust-compatible regex syntax
* derivation of wrapped exact and anywhere matcher forms
* reconstruction of Rust pattern text from Zeek wrapper text
* matcher object lifecycle and dispatch
* stream state plumbing
* unit tests

``src/RegexBackend.h`` and ``src/RegexBackend.cc`` provide the ABI seam
between C++ and Rust.

Rust
----

``rust/zeek-regex-backend/src/lib.rs`` currently owns:

* exact matching
* set matching
* stream matching
* raw FFI exports
* pointer conversion and ownership handoff
* test code

This is workable, but it makes it harder to answer a simple question: which
parts of the crate are the safe regex implementation and which parts are the
FFI shell?

Problems With The Current Shape
===============================

Three issues stand out.

First, the FFI boundary is larger than necessary. Exported ``extern "C"``
functions currently do pointer conversion, input validation, backend dispatch,
and in some cases result marshalling directly in one place.

Second, ``unsafe`` is broader than necessary. Some helpers are marked
``unsafe`` because they eventually touch raw pointers, even though most of
their logic is otherwise ordinary safe Rust.

Third, panic behavior should be tightened. Code reachable from FFI should not
rely on ``expect`` or similar behavior for operational paths. Panics at the FFI
edge are a more serious architectural concern than the raw count of ``unsafe``
blocks.

Target Architecture
===================

The long-term target is a safe Rust core with a thin, non-panicking FFI shell.

Suggested Rust crate layout:

* ``lib.rs``: module wiring plus exported ABI functions only
* ``ffi.rs``: raw pointer conversion, opaque handle ownership, output buffer
  copy-out helpers, ABI error mapping
* ``matcher.rs``: exact and set matcher construction and execution
* ``stream.rs``: stream matcher and stream state logic
* ``compat.rs``: Zeek-specific pattern normalization and wrapper
  reconstruction
* ``error.rs``: internal error types and conversions

Under this structure, the only code that should remain ``unsafe`` is code that:

* converts raw pointers into Rust references or slices
* returns or frees opaque handle pointers
* writes results into caller-provided output buffers

Everything else should be safe Rust, including the Zeek compatibility layer.

Zeek Compatibility Logic
========================

The best candidate for migration from C++ to Rust is the compatibility logic
currently living in ``src/RE.cc``. In particular:

* escape parsing and normalization
* handling for quoted regex strings
* derivation of Rust-compatible pattern text
* reconstruction from Zeek wrapper forms such as ``^?(...)$?``

This logic is parser-like, string-heavy, and semantics-sensitive. It is a good
fit for safe Rust and a comparatively risky fit for ongoing maintenance in C++.

Migrating this logic would also make the subsystem boundary cleaner:

* C++ would continue to own ``RE_Matcher`` as the current integration surface.
* Rust would own both regex execution and regex compatibility translation.

That split is easier to explain and easier to test.

FFI Guidance
============

The Rust crate should treat the FFI boundary as a small shell around safe APIs.

Recommended practices:

* add ``#![deny(unsafe_op_in_unsafe_fn)]`` so unsafe operations stay explicit
* keep ``unsafe`` blocks local instead of marking large helper functions
  ``unsafe``
* avoid ``expect`` and ``unwrap`` in FFI-reachable code paths
* convert invalid inputs and operational failures into explicit null returns,
  status codes, or empty results as appropriate for the ABI

This direction does not require introducing complex ownership transfer for
strings or large object graphs across the ABI. A narrow ABI is preferable even
if it means adding a small number of purpose-built entry points for Zeek
compatibility operations.

Migration Plan
==============

Phase 1: Rust backend cleanup
-----------------------------

Restructure the Rust crate without changing the ABI or external behavior.

Deliverables:

* split ``lib.rs`` into implementation modules
* remove FFI-path ``expect`` usage
* narrow ``unsafe`` to small blocks
* add lints that make future unsafe growth harder

This phase should be largely mechanical and low-risk.

Phase 2: Move compatibility logic to Rust
-----------------------------------------

Move Zeek-specific regex compatibility helpers out of ``src/RE.cc`` and into a
safe Rust ``compat`` module.

Deliverables:

* Rust implementation of Zeek pattern normalization
* Rust implementation of wrapper reconstruction helpers
* focused Rust unit tests for compatibility behavior
* a narrow ABI for the C++ side to request normalized or reconstructed forms

The initial goal is not to remove ``RE_Matcher``, only to reduce the amount of
semantics-heavy C++ behind it.

Phase 3: Shrink C++ glue
------------------------

Once compatibility logic lives in Rust, simplify ``src/RE.cc`` so it primarily
owns:

* ``RE_Matcher`` lifecycle and compatibility with the rest of the C++ tree
* exact-vs-anywhere matcher management
* existing public semantics and serialization touch points

At that point, ``src/RegexBackend.cc`` and ``src/RegexBackend.h`` can remain
thin wrappers or be further cleaned up to separate the raw ABI from the C++
convenience layer.

Acceptance Criteria For The First PR
====================================

The first PR in this direction should stay intentionally small.

Suggested acceptance criteria:

* no behavior changes in regex matching semantics
* no ABI changes for the existing Rust backend exports
* no panics in non-test code reachable from FFI
* reduced ``unsafe`` scope within the crate
* clearer separation between safe implementation code and FFI code

Why This Direction
==================

This approach improves three things at once:

* safety: less broad ``unsafe`` and fewer panic hazards at the FFI boundary
* architecture: a cleaner ownership split between C++ integration and Rust
  regex semantics
* reviewability: small, staged changes are easier to evaluate than a single
  full rewrite

Most importantly, it provides a path for moving the risky, string-heavy,
parser-like compatibility logic out of C++ without forcing a wholesale change
to the surrounding C++ APIs.
