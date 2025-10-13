:orphan:

Package: base/frameworks/input
==============================

The input framework provides a way to read previously stored data either as
an event stream or into a Zeek table.

:doc:`/scripts/base/frameworks/input/__load__.zeek`


:doc:`/scripts/base/frameworks/input/main.zeek`

   The input framework provides a way to read previously stored data either
   as an event stream or into a Zeek table.

:doc:`/scripts/base/frameworks/input/readers/ascii.zeek`

   Interface for the ascii input reader.
   
   The defaults are set to match Zeek's ASCII output.

:doc:`/scripts/base/frameworks/input/readers/raw.zeek`

   Interface for the raw input reader.

:doc:`/scripts/base/frameworks/input/readers/benchmark.zeek`

   Interface for the benchmark input reader.

:doc:`/scripts/base/frameworks/input/readers/binary.zeek`

   Interface for the binary input reader.

:doc:`/scripts/base/frameworks/input/readers/config.zeek`

   Interface for the config input reader.

:doc:`/scripts/base/frameworks/input/readers/sqlite.zeek`

   Interface for the SQLite input reader. Redefinable options are available
   to tweak the input format of the SQLite reader.
   
   See :doc:`/frameworks/logging-input-sqlite` for an introduction on how to
   use the SQLite reader.
   
   When using the SQLite reader, you have to specify the SQL query that returns
   the desired data by setting ``query`` in the ``config`` table. See the
   introduction mentioned above for an example.

