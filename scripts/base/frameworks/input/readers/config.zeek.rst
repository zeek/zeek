:tocdepth: 3

base/frameworks/input/readers/config.zeek
=========================================
.. bro:namespace:: InputConfig

Interface for the config input reader.

:Namespace: InputConfig

Summary
~~~~~~~
Redefinable Options
###################
================================================================================ ==========================================
:bro:id:`InputConfig::empty_field`: :bro:type:`string` :bro:attr:`&redef`        String to use for empty fields.
:bro:id:`InputConfig::fail_on_file_problem`: :bro:type:`bool` :bro:attr:`&redef` Fail on file read problems.
:bro:id:`InputConfig::set_separator`: :bro:type:`string` :bro:attr:`&redef`      Separator between set and vector elements.
================================================================================ ==========================================

Events
######
=================================================== ==============================================================
:bro:id:`InputConfig::new_value`: :bro:type:`event` Event that is called when a config option is added or changes.
=================================================== ==============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: InputConfig::empty_field

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   String to use for empty fields.
   By default this is the empty string, meaning that an empty input field
   will result in an empty set.

.. bro:id:: InputConfig::fail_on_file_problem

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Fail on file read problems. If set to true, the config
   input reader will fail when encountering any problems
   while reading a file different from invalid lines.
   Examples of such problems are permission problems, or
   missing files.
   When set to false, these problems will be ignored. This
   has an especially big effect for the REREAD mode, which will
   seamlessly recover from read errors when a file is
   only temporarily inaccessible. For MANUAL or STREAM files,
   errors will most likely still be fatal since no automatic
   re-reading of the file is attempted.
   Individual readers can use a different value using
   the $config table.

.. bro:id:: InputConfig::set_separator

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``","``

   Separator between set and vector elements.
   Please note that the separator has to be exactly one character long.

Events
######
.. bro:id:: InputConfig::new_value

   :Type: :bro:type:`event` (name: :bro:type:`string`, source: :bro:type:`string`, id: :bro:type:`string`, value: :bro:type:`any`)

   Event that is called when a config option is added or changes.
   
   Note - this does not track the reason for a change (new, changed),
   and also does not track removals. If you need this, combine the event
   with a table reader.
   

   :name: Name of the input stream.
   

   :source: Source of the input stream.
   

   :id: ID of the configuration option being set.
   

   :value: New value of the configuration option being set.


