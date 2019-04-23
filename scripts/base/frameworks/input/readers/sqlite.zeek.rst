:tocdepth: 3

base/frameworks/input/readers/sqlite.zeek
=========================================
.. zeek:namespace:: InputSQLite

Interface for the SQLite input reader. Redefinable options are available
to tweak the input format of the SQLite reader.

See :doc:`/frameworks/logging-input-sqlite` for an introduction on how to
use the SQLite reader.

When using the SQLite reader, you have to specify the SQL query that returns
the desired data by setting ``query`` in the ``config`` table. See the
introduction mentioned above for an example.

:Namespace: InputSQLite

Summary
~~~~~~~
Redefinable Options
###################
============================================================================== ===========================================
:zeek:id:`InputSQLite::empty_field`: :zeek:type:`string` :zeek:attr:`&redef`   String to use for empty fields.
:zeek:id:`InputSQLite::set_separator`: :zeek:type:`string` :zeek:attr:`&redef` Separator between set elements.
:zeek:id:`InputSQLite::unset_field`: :zeek:type:`string` :zeek:attr:`&redef`   String to use for an unset &optional field.
============================================================================== ===========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: InputSQLite::empty_field

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"(empty)"``

   String to use for empty fields.

.. zeek:id:: InputSQLite::set_separator

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``","``

   Separator between set elements.
   Please note that the separator has to be exactly one character long.

.. zeek:id:: InputSQLite::unset_field

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"-"``

   String to use for an unset &optional field.


