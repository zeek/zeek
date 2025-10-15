:tocdepth: 3

base/frameworks/input/readers/config.zeek
=========================================
.. zeek:namespace:: InputConfig

Interface for the config input reader.

:Namespace: InputConfig

Summary
~~~~~~~
Redefinable Options
###################
=================================================================================== ==========================================
:zeek:id:`InputConfig::empty_field`: :zeek:type:`string` :zeek:attr:`&redef`        String to use for empty fields.
:zeek:id:`InputConfig::fail_on_file_problem`: :zeek:type:`bool` :zeek:attr:`&redef` Fail on file read problems.
:zeek:id:`InputConfig::set_separator`: :zeek:type:`string` :zeek:attr:`&redef`      Separator between set and vector elements.
=================================================================================== ==========================================

Events
######
===================================================== ==============================================================
:zeek:id:`InputConfig::new_value`: :zeek:type:`event` Event that is called when a config option is added or changes.
===================================================== ==============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: InputConfig::empty_field
   :source-code: base/frameworks/input/readers/config.zeek 13 13

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   String to use for empty fields.
   By default this is the empty string, meaning that an empty input field
   will result in an empty set.

.. zeek:id:: InputConfig::fail_on_file_problem
   :source-code: base/frameworks/input/readers/config.zeek 28 28

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
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

.. zeek:id:: InputConfig::set_separator
   :source-code: base/frameworks/input/readers/config.zeek 8 8

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``","``

   Separator between set and vector elements.
   Please note that the separator has to be exactly one character long.

Events
######
.. zeek:id:: InputConfig::new_value
   :source-code: base/frameworks/config/input.zeek 53 59

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, source: :zeek:type:`string`, id: :zeek:type:`string`, value: :zeek:type:`any`)

   Event that is called when a config option is added or changes.
   
   Note - this does not track the reason for a change (new, changed),
   and also does not track removals. If you need this, combine the event
   with a table reader.
   

   :param name: Name of the input stream.
   

   :param source: Source of the input stream.
   

   :param id: ID of the configuration option being set.
   

   :param value: New value of the configuration option being set.


