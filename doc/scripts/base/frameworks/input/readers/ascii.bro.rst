:tocdepth: 3

base/frameworks/input/readers/ascii.bro
=======================================
.. bro:namespace:: InputAscii

Interface for the ascii input reader.

The defaults are set to match Bro's ASCII output.

:Namespace: InputAscii

Summary
~~~~~~~
Redefinable Options
###################
================================================================================ ===========================================
:bro:id:`InputAscii::empty_field`: :bro:type:`string` :bro:attr:`&redef`         String to use for empty fields.
:bro:id:`InputAscii::fail_on_file_problem`: :bro:type:`bool` :bro:attr:`&redef`  Fail on file read problems.
:bro:id:`InputAscii::fail_on_invalid_lines`: :bro:type:`bool` :bro:attr:`&redef` Fail on invalid lines.
:bro:id:`InputAscii::separator`: :bro:type:`string` :bro:attr:`&redef`           Separator between fields.
:bro:id:`InputAscii::set_separator`: :bro:type:`string` :bro:attr:`&redef`       Separator between set and vector elements.
:bro:id:`InputAscii::unset_field`: :bro:type:`string` :bro:attr:`&redef`         String to use for an unset &optional field.
================================================================================ ===========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: InputAscii::empty_field

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"(empty)"``

   String to use for empty fields.

.. bro:id:: InputAscii::fail_on_file_problem

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Fail on file read problems. If set to true, the ascii
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
   fail_on_file_problem = T was the default behavior
   until Bro 2.6.

.. bro:id:: InputAscii::fail_on_invalid_lines

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Fail on invalid lines. If set to false, the ascii
   input reader will jump over invalid lines, reporting
   warnings in reporter.log. If set to true, errors in
   input lines will be handled as fatal errors for the
   reader thread; reading will abort immediately and
   an error will be logged to reporter.log.
   Individual readers can use a different value using
   the $config table.
   fail_on_invalid_lines = T was the default behavior
   until Bro 2.6.

.. bro:id:: InputAscii::separator

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"\x09"``

   Separator between fields.
   Please note that the separator has to be exactly one character long.

.. bro:id:: InputAscii::set_separator

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``","``

   Separator between set and vector elements.
   Please note that the separator has to be exactly one character long.

.. bro:id:: InputAscii::unset_field

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"-"``

   String to use for an unset &optional field.


