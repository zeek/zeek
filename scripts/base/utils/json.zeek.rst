:tocdepth: 3

base/utils/json.zeek
====================

Functions to assist with generating JSON data from Zeek data scructures.

:Imports: :doc:`base/utils/strings.zeek </scripts/base/utils/strings.zeek>`

Summary
~~~~~~~
Functions
#########
========================================= =============================================================
:zeek:id:`to_json`: :zeek:type:`function` A function to convert arbitrary Zeek data into a JSON string.
========================================= =============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: to_json

   :Type: :zeek:type:`function` (v: :zeek:type:`any`, only_loggable: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`, field_escape_pattern: :zeek:type:`pattern` :zeek:attr:`&default` = ``/^?(^_)$?/`` :zeek:attr:`&optional`) : :zeek:type:`string`

   A function to convert arbitrary Zeek data into a JSON string.
   

   :v: The value to convert to JSON.  Typically a record.
   

   :only_loggable: If the v value is a record this will only cause
                  fields with the &log attribute to be included in the JSON.
   

   :returns: a JSON formatted string.


