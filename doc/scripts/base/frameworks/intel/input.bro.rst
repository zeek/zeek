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
=============================================================== ==============================================
:bro:id:`Intel::read_files`: :bro:type:`set` :bro:attr:`&redef` Intelligence files that will be read off disk.
=============================================================== ==============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: Intel::read_files

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Intelligence files that will be read off disk. The files are
   reread every time they are updated so updates must be atomic
   with "mv" instead of writing the file in place.


