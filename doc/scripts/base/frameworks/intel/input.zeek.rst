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

Events
######
================================================ ===================================================================
:zeek:id:`Intel::read_entry`: :zeek:type:`event` This event is raised each time the intel framework reads a new line
                                                 from an intel file.
:zeek:id:`Intel::read_error`: :zeek:type:`event` This event is raised each time the input framework detects an error
                                                 while reading the intel file.
================================================ ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Intel::path_prefix
   :source-code: base/frameworks/intel/input.zeek 22 22

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
   :source-code: base/frameworks/intel/input.zeek 12 12

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Intelligence files that will be read off disk. The files are
   reread every time they are updated so updates must be atomic
   with "mv" instead of writing the file in place.

Events
######
.. zeek:id:: Intel::read_entry
   :source-code: base/frameworks/intel/input.zeek 49 52

   :Type: :zeek:type:`event` (desc: :zeek:type:`Input::EventDescription`, tpe: :zeek:type:`Input::Event`, item: :zeek:type:`Intel::Item`)

   This event is raised each time the intel framework reads a new line
   from an intel file. It is used in the intel framework but can
   also be used in custom scripts for further checks.
   

   :param desc: The :zeek:type:`Input::EventDescription` record which generated the event.
   

   :param tpe: The type of input event.
   

   :param item: The intel item being read (of type :zeek:type:`Intel::Item`).
   

.. zeek:id:: Intel::read_error
   :source-code: base/frameworks/intel/input.zeek 46 46

   :Type: :zeek:type:`event` (desc: :zeek:type:`Input::EventDescription`, message: :zeek:type:`string`, level: :zeek:type:`Reporter::Level`)

   This event is raised each time the input framework detects an error
   while reading the intel file. It can be used to implement further checks
   in custom scripts. Errors can be of different levels (information, warning, errors).
   

   :param desc: The :zeek:type:`Input::EventDescription` record which generated the error.
   

   :param message: An error message.
   

   :param level: The :zeek:type:`Reporter::Level` of the error.
   


