:orphan:

Package: base/frameworks/intel
==============================

The intelligence framework provides a way to store and query intelligence
data (such as IP addresses or strings). Metadata can also be associated
with the intelligence.

:doc:`/scripts/base/frameworks/intel/__load__.zeek`


:doc:`/scripts/base/frameworks/intel/main.zeek`

   The intelligence framework provides a way to store and query intelligence
   data (e.g. IP addresses, URLs and hashes). The intelligence items can be
   associated with metadata to allow informed decisions about matching and
   handling.

:doc:`/scripts/base/frameworks/intel/files.zeek`

   File analysis framework integration for the intelligence framework. This
   script manages file information in intelligence framework data structures.

:doc:`/scripts/base/frameworks/intel/input.zeek`

   Input handling for the intelligence framework. This script implements the
   import of intelligence data from files using the input framework.

