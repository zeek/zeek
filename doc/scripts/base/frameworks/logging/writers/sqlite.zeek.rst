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
================================================================================================= ==========================================================================
:zeek:id:`LogSQLite::empty_field`: :zeek:type:`string` :zeek:attr:`&redef`                        String to use for empty fields.
:zeek:id:`LogSQLite::journal_mode`: :zeek:type:`LogSQLite::SQLiteJournalMode` :zeek:attr:`&redef` If changed from SQLITE_JOURNAL_MODE_DEFAULT, runs the PRAGMA
                                                                                                  journal_mode statement with the provided value after connecting to
                                                                                                  the SQLite database.
:zeek:id:`LogSQLite::set_separator`: :zeek:type:`string` :zeek:attr:`&redef`                      Separator between set elements.
:zeek:id:`LogSQLite::synchronous`: :zeek:type:`LogSQLite::SQLiteSynchronous` :zeek:attr:`&redef`  If changed from SQLITE_SYNCHRONOUS_DEFAULT, runs the PRAGMA synchronous
                                                                                                  statement with the provided value after connecting to the SQLite database.
:zeek:id:`LogSQLite::unset_field`: :zeek:type:`string` :zeek:attr:`&redef`                        String to use for an unset &optional field.
================================================================================================= ==========================================================================

Types
#####
============================================================ ============================================================
:zeek:type:`LogSQLite::SQLiteJournalMode`: :zeek:type:`enum` Values supported for SQLite's PRAGMA journal_mode statement.
:zeek:type:`LogSQLite::SQLiteSynchronous`: :zeek:type:`enum` Values supported for SQLite's PRAGMA synchronous statement.
============================================================ ============================================================


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

.. zeek:id:: LogSQLite::journal_mode
   :source-code: base/frameworks/logging/writers/sqlite.zeek 57 57

   :Type: :zeek:type:`LogSQLite::SQLiteJournalMode`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LogSQLite::SQLITE_JOURNAL_MODE_DEFAULT``

   If changed from SQLITE_JOURNAL_MODE_DEFAULT, runs the PRAGMA
   journal_mode statement with the provided value after connecting to
   the SQLite database.
   `SQLite's journal_mode documentation <https://www.sqlite.org/pragma.html#pragma_journal_mode>`_
   for more details around performance, data safety trade offs
   and interaction with the PRAGMA synchronous statement.

.. zeek:id:: LogSQLite::set_separator
   :source-code: base/frameworks/logging/writers/sqlite.zeek 16 16

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``","``

   Separator between set elements.

.. zeek:id:: LogSQLite::synchronous
   :source-code: base/frameworks/logging/writers/sqlite.zeek 49 49

   :Type: :zeek:type:`LogSQLite::SQLiteSynchronous`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LogSQLite::SQLITE_SYNCHRONOUS_DEFAULT``

   If changed from SQLITE_SYNCHRONOUS_DEFAULT, runs the PRAGMA synchronous
   statement with the provided value after connecting to the SQLite database. See
   `SQLite's synchronous documentation <https://www.sqlite.org/pragma.html#pragma_synchronous>`_
   for more details around performance and data safety trade offs.

.. zeek:id:: LogSQLite::unset_field
   :source-code: base/frameworks/logging/writers/sqlite.zeek 19 19

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"-"``

   String to use for an unset &optional field.

Types
#####
.. zeek:type:: LogSQLite::SQLiteJournalMode
   :source-code: base/frameworks/logging/writers/sqlite.zeek 35 35

   :Type: :zeek:type:`enum`

      .. zeek:enum:: LogSQLite::SQLITE_JOURNAL_MODE_DEFAULT LogSQLite::SQLiteJournalMode

      .. zeek:enum:: LogSQLite::SQLITE_JOURNAL_MODE_DELETE LogSQLite::SQLiteJournalMode

      .. zeek:enum:: LogSQLite::SQLITE_JOURNAL_MODE_TRUNCATE LogSQLite::SQLiteJournalMode

      .. zeek:enum:: LogSQLite::SQLITE_JOURNAL_MODE_PERSIST LogSQLite::SQLiteJournalMode

      .. zeek:enum:: LogSQLite::SQLITE_JOURNAL_MODE_MEMORY LogSQLite::SQLiteJournalMode

      .. zeek:enum:: LogSQLite::SQLITE_JOURNAL_MODE_WAL LogSQLite::SQLiteJournalMode

      .. zeek:enum:: LogSQLite::SQLITE_JOURNAL_MODE_OFF LogSQLite::SQLiteJournalMode

   Values supported for SQLite's PRAGMA journal_mode statement.

.. zeek:type:: LogSQLite::SQLiteSynchronous
   :source-code: base/frameworks/logging/writers/sqlite.zeek 26 26

   :Type: :zeek:type:`enum`

      .. zeek:enum:: LogSQLite::SQLITE_SYNCHRONOUS_DEFAULT LogSQLite::SQLiteSynchronous

      .. zeek:enum:: LogSQLite::SQLITE_SYNCHRONOUS_OFF LogSQLite::SQLiteSynchronous

      .. zeek:enum:: LogSQLite::SQLITE_SYNCHRONOUS_NORMAL LogSQLite::SQLiteSynchronous

      .. zeek:enum:: LogSQLite::SQLITE_SYNCHRONOUS_FULL LogSQLite::SQLiteSynchronous

      .. zeek:enum:: LogSQLite::SQLITE_SYNCHRONOUS_EXTRA LogSQLite::SQLiteSynchronous

   Values supported for SQLite's PRAGMA synchronous statement.


