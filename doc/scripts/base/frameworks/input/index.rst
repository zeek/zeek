:orphan:

Package: base/frameworks/input
==============================

The input framework provides a way to read previously stored data either as
an event stream or into a Bro table.

:doc:`/scripts/base/frameworks/input/__load__.bro`


:doc:`/scripts/base/frameworks/input/main.bro`

   The input framework provides a way to read previously stored data either
   as an event stream or into a Bro table.

:doc:`/scripts/base/frameworks/input/readers/ascii.bro`

   Interface for the ascii input reader.
   
   The defaults are set to match Bro's ASCII output.

:doc:`/scripts/base/frameworks/input/readers/raw.bro`

   Interface for the raw input reader.

:doc:`/scripts/base/frameworks/input/readers/benchmark.bro`

   Interface for the benchmark input reader.

:doc:`/scripts/base/frameworks/input/readers/binary.bro`

   Interface for the binary input reader.

:doc:`/scripts/base/frameworks/input/readers/config.bro`

   Interface for the config input reader.

:doc:`/scripts/base/frameworks/input/readers/sqlite.bro`

   Interface for the SQLite input reader. Redefinable options are available
   to tweak the input format of the SQLite reader.
   
   See :doc:`/frameworks/logging-input-sqlite` for an introduction on how to
   use the SQLite reader.
   
   When using the SQLite reader, you have to specify the SQL query that returns
   the desired data by setting ``query`` in the ``config`` table. See the
   introduction mentioned above for an example.

