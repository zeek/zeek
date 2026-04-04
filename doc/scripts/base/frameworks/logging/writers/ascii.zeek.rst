:tocdepth: 3

base/frameworks/logging/writers/ascii.zeek
==========================================
.. zeek:namespace:: LogAscii

Interface for the ASCII log writer.  Redefinable options are available
to tweak the output format of ASCII logs.

The ASCII writer currently supports one writer-specific per-filter config
option: setting ``tsv`` to the string ``T`` turns the output into
"tab-separated-value" mode where only a single header row with the column
names is printed out as meta information, with no "# fields" prepended; no
other meta data gets included in that mode.  Example filter using this::

   local f = Log::Filter($name = "my-filter",
                         $writer = Log::WRITER_ASCII,
                         $config = table(["tsv"] = "T"));


:Namespace: LogAscii

Summary
~~~~~~~
Redefinable Options
###################
============================================================================================ =====================================================================
:zeek:id:`LogAscii::empty_field`: :zeek:type:`string` :zeek:attr:`&redef`                    String to use for empty fields.
:zeek:id:`LogAscii::enable_leftover_log_rotation`: :zeek:type:`bool` :zeek:attr:`&redef`     If true, detect log files that did not get properly rotated
                                                                                             by a previous Zeek process (e.g.
:zeek:id:`LogAscii::enable_utf_8`: :zeek:type:`bool` :zeek:attr:`&redef`                     If true, valid UTF-8 sequences will pass through unescaped and be
                                                                                             written into logs.
:zeek:id:`LogAscii::gzip_file_extension`: :zeek:type:`string` :zeek:attr:`&redef`            Define the file extension used when compressing log files when
                                                                                             they are created with the :zeek:see:`LogAscii::gzip_level` option.
:zeek:id:`LogAscii::gzip_level`: :zeek:type:`count` :zeek:attr:`&redef`                      Define the gzip level to compress the logs.
:zeek:id:`LogAscii::include_meta`: :zeek:type:`bool` :zeek:attr:`&redef`                     If true, include lines with log meta information such as column names
                                                                                             with types, the values of ASCII logging options that are in use, and
                                                                                             the time when the file was opened and closed (the latter at the end).
:zeek:id:`LogAscii::json_include_unset_fields`: :zeek:type:`bool` :zeek:attr:`&redef`        Handling of optional fields when writing out JSON.
:zeek:id:`LogAscii::json_timestamps`: :zeek:type:`JSON::TimestampFormat` :zeek:attr:`&redef` Format of timestamps when writing out JSON.
:zeek:id:`LogAscii::meta_prefix`: :zeek:type:`string` :zeek:attr:`&redef`                    Prefix for lines with meta information.
:zeek:id:`LogAscii::output_to_stdout`: :zeek:type:`bool` :zeek:attr:`&redef`                 If true, output everything to stdout rather than
                                                                                             into files.
:zeek:id:`LogAscii::separator`: :zeek:type:`string` :zeek:attr:`&redef`                      Separator between fields.
:zeek:id:`LogAscii::set_separator`: :zeek:type:`string` :zeek:attr:`&redef`                  Separator between set elements.
:zeek:id:`LogAscii::unset_field`: :zeek:type:`string` :zeek:attr:`&redef`                    String to use for an unset &optional field.
:zeek:id:`LogAscii::use_json`: :zeek:type:`bool` :zeek:attr:`&redef`                         If true, the default will be to write logs in a JSON format.
============================================================================================ =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: LogAscii::empty_field
   :source-code: base/frameworks/logging/writers/ascii.zeek 95 95

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"(empty)"``

   String to use for empty fields. This should be different from
   *unset_field* to make the output unambiguous.

   This option is also available as a per-filter ``$config`` option.

.. zeek:id:: LogAscii::enable_leftover_log_rotation
   :source-code: base/frameworks/logging/writers/ascii.zeek 35 35

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``
   :Redefinition: from :doc:`/scripts/policy/misc/systemd-generator.zeek`

      ``=``::

         ``T``


   If true, detect log files that did not get properly rotated
   by a previous Zeek process (e.g. due to crash) and rotate them.

   This requires a positive rotation interval to be configured
   to have an effect.  E.g. via :zeek:see:`Log::default_rotation_interval`
   or the *interv* field of a :zeek:see:`Log::Filter`.

.. zeek:id:: LogAscii::enable_utf_8
   :source-code: base/frameworks/logging/writers/ascii.zeek 41 41

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If true, valid UTF-8 sequences will pass through unescaped and be
   written into logs.

   This option is also available as a per-filter ``$config`` option.

.. zeek:id:: LogAscii::gzip_file_extension
   :source-code: base/frameworks/logging/writers/ascii.zeek 55 55

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"gz"``

   Define the file extension used when compressing log files when
   they are created with the :zeek:see:`LogAscii::gzip_level` option.

   This option is also available as a per-filter ``$config`` option.

.. zeek:id:: LogAscii::gzip_level
   :source-code: base/frameworks/logging/writers/ascii.zeek 49 49

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0``

   Define the gzip level to compress the logs.  If 0, then no gzip
   compression is performed. Enabling compression also changes
   the log file name extension to include the value of
   :zeek:see:`LogAscii::gzip_file_extension`.

   This option is also available as a per-filter ``$config`` option.

.. zeek:id:: LogAscii::include_meta
   :source-code: base/frameworks/logging/writers/ascii.zeek 74 74

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If true, include lines with log meta information such as column names
   with types, the values of ASCII logging options that are in use, and
   the time when the file was opened and closed (the latter at the end).

   If writing in JSON format, this is implicitly disabled.

.. zeek:id:: LogAscii::json_include_unset_fields
   :source-code: base/frameworks/logging/writers/ascii.zeek 67 67

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Handling of optional fields when writing out JSON. By default the
   JSON formatter skips key and val when the field is absent. Setting
   the following field to T includes the key, with a null value.

.. zeek:id:: LogAscii::json_timestamps
   :source-code: base/frameworks/logging/writers/ascii.zeek 62 62

   :Type: :zeek:type:`JSON::TimestampFormat`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``JSON::TS_EPOCH``

   Format of timestamps when writing out JSON. By default, the JSON
   formatter will use double values for timestamps which represent the
   number of seconds from the UNIX epoch.

   This option is also available as a per-filter ``$config`` option.

.. zeek:id:: LogAscii::meta_prefix
   :source-code: base/frameworks/logging/writers/ascii.zeek 79 79

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"#"``

   Prefix for lines with meta information.

   This option is also available as a per-filter ``$config`` option.

.. zeek:id:: LogAscii::output_to_stdout
   :source-code: base/frameworks/logging/writers/ascii.zeek 22 22

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, output everything to stdout rather than
   into files. This is primarily for debugging purposes.

   This option is also available as a per-filter ``$config`` option.

.. zeek:id:: LogAscii::separator
   :source-code: base/frameworks/logging/writers/ascii.zeek 84 84

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"\x09"``

   Separator between fields.

   This option is also available as a per-filter ``$config`` option.

.. zeek:id:: LogAscii::set_separator
   :source-code: base/frameworks/logging/writers/ascii.zeek 89 89

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``","``

   Separator between set elements.

   This option is also available as a per-filter ``$config`` option.

.. zeek:id:: LogAscii::unset_field
   :source-code: base/frameworks/logging/writers/ascii.zeek 100 100

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"-"``

   String to use for an unset &optional field.

   This option is also available as a per-filter ``$config`` option.

.. zeek:id:: LogAscii::use_json
   :source-code: base/frameworks/logging/writers/ascii.zeek 27 27

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``
   :Redefinition: from :doc:`/scripts/policy/tuning/json-logs.zeek`

      ``=``::

         ``T``


   If true, the default will be to write logs in a JSON format.

   This option is also available as a per-filter ``$config`` option.


