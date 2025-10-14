:tocdepth: 3

base/frameworks/logging/writers/sqlite.zeek
===========================================
.. zeek:namespace:: LogSQLite

Interface for the SQLite log writer. Redefinable options are available
to tweak the output format of the SQLite reader.

See :doc:`/frameworks/logging-input-sqlite` for an introduction on how to
use the SQLite log writer.

The SQL writer currently supports one writer-specific filter option via
``config``: setting ``tablename`` sets the name of the table that is used
or created in the SQLite database. An example for this is given in the
introduction mentioned above.

:Namespace: LogSQLite

Summary
~~~~~~~
Redefinable Options
###################
============================================================================ ===========================================
:zeek:id:`LogSQLite::empty_field`: :zeek:type:`string` :zeek:attr:`&redef`   String to use for empty fields.
:zeek:id:`LogSQLite::set_separator`: :zeek:type:`string` :zeek:attr:`&redef` Separator between set elements.
:zeek:id:`LogSQLite::unset_field`: :zeek:type:`string` :zeek:attr:`&redef`   String to use for an unset &optional field.
============================================================================ ===========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: LogSQLite::empty_field
   :source-code: base/frameworks/logging/writers/sqlite.zeek 23 23

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"(empty)"``

   String to use for empty fields. This should be different from
   *unset_field* to make the output unambiguous.

.. zeek:id:: LogSQLite::set_separator
   :source-code: base/frameworks/logging/writers/sqlite.zeek 16 16

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``","``

   Separator between set elements.

.. zeek:id:: LogSQLite::unset_field
   :source-code: base/frameworks/logging/writers/sqlite.zeek 19 19

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"-"``

   String to use for an unset &optional field.


