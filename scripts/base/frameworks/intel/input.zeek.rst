:tocdepth: 3

base/frameworks/intel/input.zeek
================================
.. zeek:namespace:: Intel

Input handling for the intelligence framework. This script implements the
import of intelligence data from files using the input framework.

:Namespace: Intel
:Imports: :doc:`base/frameworks/intel/main.zeek </scripts/base/frameworks/intel/main.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
====================================================================== ==============================================
:zeek:id:`Intel::path_prefix`: :zeek:type:`string` :zeek:attr:`&redef` An optional path prefix for intel files.
:zeek:id:`Intel::read_files`: :zeek:type:`set` :zeek:attr:`&redef`     Intelligence files that will be read off disk.
====================================================================== ==============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Intel::path_prefix

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   An optional path prefix for intel files. This prefix can, but
   need not be, absolute. The default is to leave any filenames
   unchanged. This prefix has no effect if a read_file entry is
   an absolute path. This prefix gets applied _before_ entering
   the input framework, so if the prefix is absolute, the input
   framework won't munge it further. If it is relative, then
   any path_prefix specified in the input framework will apply
   additionally.

.. zeek:id:: Intel::read_files

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Intelligence files that will be read off disk. The files are
   reread every time they are updated so updates must be atomic
   with "mv" instead of writing the file in place.


