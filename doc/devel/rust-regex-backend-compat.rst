.. _rust_regex_backend_compat:

=================================
Rust Regex Backend Compatibility
=================================

This document is a companion to :doc:`rust-regex-backend` and
:doc:`rust-regex-backend-plan`. It inventories the compatibility behavior that
the Rust regex backend currently preserves, along with the places where Zeek
can likely simplify or deliberately change behavior later.

The goal is to make the remaining compatibility glue explicit. That helps with
review, clarifies why certain code exists, and gives future work a concrete
list of candidates for cleanup.


Compatibility Buckets
=====================

The compatibility work in the Rust backend falls into three broad buckets:

``required``
    Semantics that Zeek depends on for core functionality or user-facing
    language behavior. These should remain unless Zeek deliberately changes the
    language contract.

``accepted drift``
    Areas where the Rust backend intentionally does not preserve the old engine
    exactly. These differences are acceptable and should not block the
    migration.

``cleanup candidates``
    Historical behaviors or representation choices that Zeek can likely
    simplify, deprecate, or replace once the Rust backend has landed and
    stabilized.


Required Compatibility
======================

These behaviors are core to the current Zeek programming model and should be
treated as part of the compatibility target.

Matcher API shape
-----------------

The C++ facade remains the integration boundary for the rest of Zeek:

* ``RE_Matcher``
* ``detail::Specific_RE_Matcher``
* ``detail::RE_Match_State``

This is important because most call sites in the tree care about match
behavior, not about automata internals. Preserving this boundary keeps the Rust
backend localized.


Exact, anywhere, and longest-prefix matching
--------------------------------------------

Zeek depends on three distinct matching contracts:

* exact match for ``string == pattern``,
* anywhere match for ``pattern in string`` and related helpers, and
* longest-prefix match for prefix-oriented consumers.

These are not interchangeable, and the Rust backend keeps them distinct.
Maintaining that split is required.


Regex-set behavior for ``table[pattern]`` and ``set[pattern]``
--------------------------------------------------------------

The Rust backend preserves:

* exact set matching,
* non-zero accept-id numbering, and
* the ability to return all matching pattern ids.

That behavior is part of the contract for ``table[pattern]`` and
``set[pattern]`` lookup and should remain stable.


Streaming and signature matching
--------------------------------

Incremental matching semantics are required for signatures, file magic, and
other streaming consumers. The current Rust backend preserves:

* per-stream match state,
* packet or chunk boundary handling,
* begin-of-input and end-of-input sensitivity, and
* matcher-global shared lazy DFA cache reuse for stream patterns.

This area contains some Zeek-specific compatibility code, but the overall
behavior is fundamental and not optional.


Pattern composition and reconstruction
--------------------------------------

Zeek stores and rebuilds patterns in several places. The Rust backend preserves
enough information for:

* ``pattern`` values,
* ``pattern += pattern``,
* ``pattern & pattern`` / ``pattern | pattern``,
* Broker roundtrips, and
* reconstruction from Zeek's exact and anywhere wrapper forms.

This is required to keep pattern values working naturally across the language,
serialization, and container paths.


Quoted regex strings
--------------------

Zeek has a non-standard regex feature where ``"..."`` inside a pattern denotes
literal byte text that remains case-sensitive even inside ``/.../i``. This is
weird, but it is a real language feature and has tests.

The Rust backend currently preserves it by translating it at the Zeek boundary
instead of teaching the Rust engine a new syntax. If the language contract is
kept, this translation layer is required.


Accepted Drift
==============

These are differences from the legacy engine that are acceptable today.

Matcher stats
-------------

The old engine exposed detailed DFA cache statistics. The Rust backend does not
attempt to reproduce those numbers exactly, and some current metrics may be
zero or backend-neutral placeholders.

This is acceptable drift. The important thing is that Zeek continues to work;
exact cache counters are not part of the critical compatibility target.


Debug and introspection internals
---------------------------------

The legacy engine exposed DFA-oriented implementation details. Those do not map
cleanly onto the Rust backend and are not required to survive unchanged.

In particular, developer-facing debugging output may become more backend-neutral
or disappear where it no longer makes sense.


Internal pattern text normalization
-----------------------------------

Some reconstructed or merged pattern texts may differ slightly from the legacy
engine's internal representation even when the visible behavior is preserved.

That is acceptable as long as:

* user-visible script behavior stays correct,
* serialization roundtrips remain safe, and
* equality and lookup semantics continue to behave as Zeek expects.


Cleanup Candidates
==================

These are the best current opportunities to reduce glue after the Rust backend
has landed.

Quoted regex strings
--------------------

The feature is supported today, but it remains a strong deprecation candidate.
It is non-standard, surprising, and adds frontend translation code that most
users likely never notice.

If Zeek chooses to simplify its regex language, this is one of the most obvious
places to start.


Wrapper-text reconstruction
---------------------------

Zeek historically stores exact and anywhere wrapper strings of the form
``^?(...)$?`` and ``^?(.|\\n)*(...)``. The Rust backend can re-derive raw Rust
pattern text from those wrappers, but that translation is glue.

Longer term, Zeek could reduce complexity by making the preserved raw pattern
representation more explicit and relying less on wrapper-text recovery.


Boundary-specific stream compatibility code
-------------------------------------------

Chunk-boundary and packet-boundary behavior in signatures is a real Zeek
contract, but some of the current implementation is still compatibility logic
layered around that contract.

Future cleanup could make boundary behavior more explicit at the API level so
that less special handling is encoded in the matcher itself.


Generic matcher stats API
-------------------------

The current backend-neutral stats story is minimal. If Zeek wants introspection
to remain useful, a small generic matcher-stats API would be cleaner than
continuing to preserve legacy DFA terminology.


How To Use This Document
========================

When considering removal or simplification of compatibility code, use this
document as a checklist:

1. Decide whether the behavior is ``required``, ``accepted drift``, or a
   ``cleanup candidate``.
2. If it is a cleanup candidate, decide whether Zeek wants to deprecate it or
   redesign it.
3. Confirm that the relevant tests describe the intended contract.
4. Remove or simplify the glue only after the contract decision is explicit.

The important idea is that compatibility code should be intentional. Zeek does
not need to keep every historical behavior forever, but it should know which
ones it is choosing to keep and why.
