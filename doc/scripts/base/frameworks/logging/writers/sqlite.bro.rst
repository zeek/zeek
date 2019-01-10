:tocdepth: 3

base/frameworks/logging/writers/sqlite.bro
==========================================
.. bro:namespace:: LogSQLite

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
========================================================================= ===========================================
:bro:id:`LogSQLite::empty_field`: :bro:type:`string` :bro:attr:`&redef`   String to use for empty fields.
:bro:id:`LogSQLite::set_separator`: :bro:type:`string` :bro:attr:`&redef` Separator between set elements.
:bro:id:`LogSQLite::unset_field`: :bro:type:`string` :bro:attr:`&redef`   String to use for an unset &optional field.
========================================================================= ===========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: LogSQLite::empty_field

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"(empty)"``

   String to use for empty fields. This should be different from
   *unset_field* to make the output unambiguous.

.. bro:id:: LogSQLite::set_separator

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``","``

   Separator between set elements.

.. bro:id:: LogSQLite::unset_field

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"-"``

   String to use for an unset &optional field.


