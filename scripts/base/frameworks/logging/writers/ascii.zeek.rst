:tocdepth: 3

base/frameworks/logging/writers/ascii.zeek
==========================================
.. bro:namespace:: LogAscii

Interface for the ASCII log writer.  Redefinable options are available
to tweak the output format of ASCII logs.

The ASCII writer currently supports one writer-specific per-filter config
option: setting ``tsv`` to the string ``T`` turns the output into
"tab-separated-value" mode where only a single header row with the column
names is printed out as meta information, with no "# fields" prepended; no
other meta data gets included in that mode.  Example filter using this::

   local f: Log::Filter = [$name = "my-filter",
                           $writer = Log::WRITER_ASCII,
                           $config = table(["tsv"] = "T")];


:Namespace: LogAscii

Summary
~~~~~~~
Redefinable Options
###################
========================================================================================= =====================================================================
:bro:id:`LogAscii::empty_field`: :bro:type:`string` :bro:attr:`&redef`                    String to use for empty fields.
:bro:id:`LogAscii::gzip_level`: :bro:type:`count` :bro:attr:`&redef`                      Define the gzip level to compress the logs.
:bro:id:`LogAscii::include_meta`: :bro:type:`bool` :bro:attr:`&redef`                     If true, include lines with log meta information such as column names
                                                                                          with types, the values of ASCII logging options that are in use, and
                                                                                          the time when the file was opened and closed (the latter at the end).
:bro:id:`LogAscii::json_timestamps`: :bro:type:`JSON::TimestampFormat` :bro:attr:`&redef` Format of timestamps when writing out JSON.
:bro:id:`LogAscii::meta_prefix`: :bro:type:`string` :bro:attr:`&redef`                    Prefix for lines with meta information.
:bro:id:`LogAscii::output_to_stdout`: :bro:type:`bool` :bro:attr:`&redef`                 If true, output everything to stdout rather than
                                                                                          into files.
:bro:id:`LogAscii::separator`: :bro:type:`string` :bro:attr:`&redef`                      Separator between fields.
:bro:id:`LogAscii::set_separator`: :bro:type:`string` :bro:attr:`&redef`                  Separator between set elements.
:bro:id:`LogAscii::unset_field`: :bro:type:`string` :bro:attr:`&redef`                    String to use for an unset &optional field.
:bro:id:`LogAscii::use_json`: :bro:type:`bool` :bro:attr:`&redef`                         If true, the default will be to write logs in a JSON format.
========================================================================================= =====================================================================

Redefinitions
#############
==================================================================================== =
:bro:id:`Log::default_rotation_postprocessors`: :bro:type:`table` :bro:attr:`&redef` 
==================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: LogAscii::empty_field

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"(empty)"``

   String to use for empty fields. This should be different from
   *unset_field* to make the output unambiguous.
   
   This option is also available as a per-filter ``$config`` option.

.. bro:id:: LogAscii::gzip_level

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0``

   Define the gzip level to compress the logs.  If 0, then no gzip
   compression is performed. Enabling compression also changes
   the log file name extension to include ".gz".
   
   This option is also available as a per-filter ``$config`` option.

.. bro:id:: LogAscii::include_meta

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   If true, include lines with log meta information such as column names
   with types, the values of ASCII logging options that are in use, and
   the time when the file was opened and closed (the latter at the end).
   
   If writing in JSON format, this is implicitly disabled.

.. bro:id:: LogAscii::json_timestamps

   :Type: :bro:type:`JSON::TimestampFormat`
   :Attributes: :bro:attr:`&redef`
   :Default: ``JSON::TS_EPOCH``

   Format of timestamps when writing out JSON. By default, the JSON
   formatter will use double values for timestamps which represent the
   number of seconds from the UNIX epoch.
   
   This option is also available as a per-filter ``$config`` option.

.. bro:id:: LogAscii::meta_prefix

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"#"``

   Prefix for lines with meta information.
   
   This option is also available as a per-filter ``$config`` option.

.. bro:id:: LogAscii::output_to_stdout

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, output everything to stdout rather than
   into files. This is primarily for debugging purposes.
   
   This option is also available as a per-filter ``$config`` option.

.. bro:id:: LogAscii::separator

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"\x09"``

   Separator between fields.
   
   This option is also available as a per-filter ``$config`` option.

.. bro:id:: LogAscii::set_separator

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``","``

   Separator between set elements.
   
   This option is also available as a per-filter ``$config`` option.

.. bro:id:: LogAscii::unset_field

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"-"``

   String to use for an unset &optional field.
   
   This option is also available as a per-filter ``$config`` option.

.. bro:id:: LogAscii::use_json

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   If true, the default will be to write logs in a JSON format.
   
   This option is also available as a per-filter ``$config`` option.


