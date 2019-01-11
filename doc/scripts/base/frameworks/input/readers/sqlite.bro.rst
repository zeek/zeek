:tocdepth: 3

base/frameworks/input/readers/sqlite.bro
========================================
.. bro:namespace:: InputSQLite

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
=========================================================================== ===========================================
:bro:id:`InputSQLite::empty_field`: :bro:type:`string` :bro:attr:`&redef`   String to use for empty fields.
:bro:id:`InputSQLite::set_separator`: :bro:type:`string` :bro:attr:`&redef` Separator between set elements.
:bro:id:`InputSQLite::unset_field`: :bro:type:`string` :bro:attr:`&redef`   String to use for an unset &optional field.
=========================================================================== ===========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: InputSQLite::empty_field

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"(empty)"``

   String to use for empty fields.

.. bro:id:: InputSQLite::set_separator

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``","``

   Separator between set elements.
   Please note that the separator has to be exactly one character long.

.. bro:id:: InputSQLite::unset_field

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"-"``

   String to use for an unset &optional field.


