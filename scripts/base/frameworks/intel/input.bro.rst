:tocdepth: 3

base/frameworks/intel/input.bro
===============================
.. bro:namespace:: Intel

Input handling for the intelligence framework. This script implements the
import of intelligence data from files using the input framework.

:Namespace: Intel
:Imports: :doc:`base/frameworks/intel/main.bro </scripts/base/frameworks/intel/main.bro>`

Summary
~~~~~~~
Redefinable Options
###################
=================================================================== ==============================================
:bro:id:`Intel::path_prefix`: :bro:type:`string` :bro:attr:`&redef` An optional path prefix for intel files.
:bro:id:`Intel::read_files`: :bro:type:`set` :bro:attr:`&redef`     Intelligence files that will be read off disk.
=================================================================== ==============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: Intel::path_prefix

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   An optional path prefix for intel files. This prefix can, but
   need not be, absolute. The default is to leave any filenames
   unchanged. This prefix has no effect if a read_file entry is
   an absolute path. This prefix gets applied _before_ entering
   the input framework, so if the prefix is absolute, the input
   framework won't munge it further. If it is relative, then
   any path_prefix specified in the input framework will apply
   additionally.

.. bro:id:: Intel::read_files

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Intelligence files that will be read off disk. The files are
   reread every time they are updated so updates must be atomic
   with "mv" instead of writing the file in place.


