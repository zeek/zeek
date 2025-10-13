:tocdepth: 3

base/frameworks/input/readers/ascii.zeek
========================================
.. zeek:namespace:: InputAscii

Interface for the ascii input reader.

The defaults are set to match Zeek's ASCII output.

:Namespace: InputAscii

Summary
~~~~~~~
Redefinable Options
###################
=================================================================================== ==================================================================
:zeek:id:`InputAscii::empty_field`: :zeek:type:`string` :zeek:attr:`&redef`         String to use for empty fields.
:zeek:id:`InputAscii::fail_on_file_problem`: :zeek:type:`bool` :zeek:attr:`&redef`  Fail on file read problems.
:zeek:id:`InputAscii::fail_on_invalid_lines`: :zeek:type:`bool` :zeek:attr:`&redef` Fail on invalid lines.
:zeek:id:`InputAscii::path_prefix`: :zeek:type:`string` :zeek:attr:`&redef`         On input streams with a pathless or relative-path source filename,
                                                                                    prefix the following path.
:zeek:id:`InputAscii::separator`: :zeek:type:`string` :zeek:attr:`&redef`           Separator between fields.
:zeek:id:`InputAscii::set_separator`: :zeek:type:`string` :zeek:attr:`&redef`       Separator between set and vector elements.
:zeek:id:`InputAscii::unset_field`: :zeek:type:`string` :zeek:attr:`&redef`         String to use for an unset &optional field.
=================================================================================== ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: InputAscii::empty_field
   :source-code: base/frameworks/input/readers/ascii.zeek 17 17

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"(empty)"``

   String to use for empty fields.

.. zeek:id:: InputAscii::fail_on_file_problem
   :source-code: base/frameworks/input/readers/ascii.zeek 49 49

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
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

.. zeek:id:: InputAscii::fail_on_invalid_lines
   :source-code: base/frameworks/input/readers/ascii.zeek 32 32

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
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

.. zeek:id:: InputAscii::path_prefix
   :source-code: base/frameworks/input/readers/ascii.zeek 55 55

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   On input streams with a pathless or relative-path source filename,
   prefix the following path. This prefix can, but need not be, absolute.
   The default is to leave any filenames unchanged. This prefix has no
   effect if the source already is an absolute path.

.. zeek:id:: InputAscii::separator
   :source-code: base/frameworks/input/readers/ascii.zeek 10 10

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"\x09"``

   Separator between fields.
   Please note that the separator has to be exactly one character long.

.. zeek:id:: InputAscii::set_separator
   :source-code: base/frameworks/input/readers/ascii.zeek 14 14

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``","``

   Separator between set and vector elements.
   Please note that the separator has to be exactly one character long.

.. zeek:id:: InputAscii::unset_field
   :source-code: base/frameworks/input/readers/ascii.zeek 20 20

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"-"``

   String to use for an unset &optional field.


