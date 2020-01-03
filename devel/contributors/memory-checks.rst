====================================
How-To Check for Memory Errors/Leaks
====================================

Configure Zeek with AddressSanitizer
====================================

Zeek can use AddressSanitizer (includes LeakSanitizer by default) to check for
memory errors and/or leaks.  Simply configure like::

  ./configure --build-type=debug --sanitizers=address

Any execution of the Zeek binary then checks for memory-related errors and
leaks automatically.  This includes any runs of regression test suite(s).

Either GCC or Clang compilers support address/leak sanitizers, except Apple's
clang may not implement the leak sanitizer.  For the CI infrastructure, GCC
gets used to run the sanitizer checks.  GCC may also produce a binary with
marginally faster run-time performance (~4-5%).

By default, the ``--sanitizers`` configure flag will set ``-O1`` but you
can disable that like::

  NO_OPTIMIZATIONS=1 ./configure --build-type=debug --sanitizers=address

The idea is that using ``-O1`` helps make up for some of the additional
overhead of the sanitizer checks, but still allows for "perfect" stack traces.
Using ``-O0`` on a sanitizer-build is ~2.3x slower than a non-sanitizer-build
(also with ``-O0``), but using ``-O1`` is only ~1.6x slower (measurements done
with GCC 8.3.0).  A possible downside to ``-O1`` is it could optimize out real
memory errors/leaks, but it's unlikely and people aren't expected to run
``-O0`` in production anyway.

Misc. Notes
===========

- See `ASAN_OPTIONS <https://github.com/google/sanitizers/wiki/AddressSanitizerFlags>`_
  for various tuning options.  Common/helpful settings:

    - To disable just the leak check functionality: ``ASAN_OPTIONS="detect_leaks=0"``

    - If call stacks are truncated: ``ASAN_OPTIONS="malloc_context_size=42"``
      (default value seems to be 30 and Zeek stacks can get bigger than that)

    - Some sanitizer implementations may warn about some ODR violations from
      the duplicate SQLite code (both in Broker and in Zeek).  Can set
      ``ASAN_OPTIONS="detect_odr_violation=0"``.

- Broker unit tests can also be run with sanitizers enabled (same configuration
  command as above), but tests for the python bindings may need to run like::

    LD_PRELOAD=/lib/x86_64-linux-gnu/libasan.so.5 ASAN_OPTIONS="detect_leaks=0" ctest -R python

- There's no need to write tests in any special way.  LeakSanitizer will be
  enabled before ``zeek_init()`` and even just before any top-level script
  statements get executed, so any arbitrary Zeek script you can write as part
  of the test suite automatically gets full memory error/leak checking
  coverage.
