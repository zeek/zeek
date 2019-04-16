:tocdepth: 3

base/utils/json.zeek
====================

Functions to assist with generating JSON data from Bro data scructures.

:Imports: :doc:`base/utils/strings.zeek </scripts/base/utils/strings.zeek>`

Summary
~~~~~~~
Functions
#########
======================================= ============================================================
:bro:id:`to_json`: :bro:type:`function` A function to convert arbitrary Bro data into a JSON string.
======================================= ============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: to_json

   :Type: :bro:type:`function` (v: :bro:type:`any`, only_loggable: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`, field_escape_pattern: :bro:type:`pattern` :bro:attr:`&default` = ``/^?(^_)$?/`` :bro:attr:`&optional`) : :bro:type:`string`

   A function to convert arbitrary Bro data into a JSON string.
   

   :v: The value to convert to JSON.  Typically a record.
   

   :only_loggable: If the v value is a record this will only cause
                  fields with the &log attribute to be included in the JSON.
   

   :returns: a JSON formatted string.


