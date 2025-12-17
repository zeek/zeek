:tocdepth: 3

base/protocols/postgresql/main.zeek
===================================
.. zeek:namespace:: PostgreSQL

Implements base functionality for PostgreSQL analysis.

:Namespace: PostgreSQL
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/postgresql/consts.zeek </scripts/base/protocols/postgresql/consts.zeek>`, :doc:`base/protocols/postgresql/spicy-events.zeek </scripts/base/protocols/postgresql/spicy-events.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
================================================================== ================================
:zeek:id:`PostgreSQL::ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for PostgreSQL.
================================================================== ================================

Types
#####
===================================================== ===============================================================
:zeek:type:`PostgreSQL::Info`: :zeek:type:`record`    Record type containing the column fields of the PostgreSQL log.
:zeek:type:`PostgreSQL::State`: :zeek:type:`record`   
:zeek:type:`PostgreSQL::Version`: :zeek:type:`record` 
===================================================== ===============================================================

Redefinitions
#############
============================================ =========================================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      Log stream identifier.
                                             
                                             * :zeek:enum:`PostgreSQL::LOG`
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               postgresql: :zeek:type:`PostgreSQL::Info` :zeek:attr:`&optional`
                                             
                                               postgresql_state: :zeek:type:`PostgreSQL::State` :zeek:attr:`&optional`
============================================ =========================================================================

Events
######
========================================================= =====================================
:zeek:id:`PostgreSQL::log_postgresql`: :zeek:type:`event` Default hook into PostgreSQL logging.
========================================================= =====================================

Hooks
#####
========================================================================== =
:zeek:id:`PostgreSQL::finalize_postgresql`: :zeek:type:`Conn::RemovalHook` 
========================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PostgreSQL::ports
   :source-code: base/protocols/postgresql/main.zeek 15 15

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            5432/tcp
         }


   Well-known ports for PostgreSQL.

Types
#####
.. zeek:type:: PostgreSQL::Info
   :source-code: base/protocols/postgresql/main.zeek 23 52

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when the activity happened.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: user :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      The user as found in the StartupMessage.


   .. zeek:field:: database :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      The database as found in the StartupMessage.


   .. zeek:field:: application_name :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      The application name as found in the StartupMessage.


   .. zeek:field:: frontend :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: frontend_arg :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: backend :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: backend_arg :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: success :zeek:type:`bool` :zeek:attr:`&optional` :zeek:attr:`&log`


   .. zeek:field:: rows :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`


   Record type containing the column fields of the PostgreSQL log.

.. zeek:type:: PostgreSQL::State
   :source-code: base/protocols/postgresql/main.zeek 54 61

   :Type: :zeek:type:`record`


   .. zeek:field:: version :zeek:type:`PostgreSQL::Version` :zeek:attr:`&optional`


   .. zeek:field:: user :zeek:type:`string` :zeek:attr:`&optional`


   .. zeek:field:: database :zeek:type:`string` :zeek:attr:`&optional`


   .. zeek:field:: application_name :zeek:type:`string` :zeek:attr:`&optional`


   .. zeek:field:: rows :zeek:type:`count` :zeek:attr:`&optional`


   .. zeek:field:: errors :zeek:type:`vector` of :zeek:type:`string`



.. zeek:type:: PostgreSQL::Version
   :source-code: base/protocols/postgresql/main.zeek 17 20

   :Type: :zeek:type:`record`


   .. zeek:field:: major :zeek:type:`count`


   .. zeek:field:: minor :zeek:type:`count`



Events
######
.. zeek:id:: PostgreSQL::log_postgresql
   :source-code: base/protocols/postgresql/main.zeek 64 64

   :Type: :zeek:type:`event` (rec: :zeek:type:`PostgreSQL::Info`)

   Default hook into PostgreSQL logging.

Hooks
#####
.. zeek:id:: PostgreSQL::finalize_postgresql
   :source-code: base/protocols/postgresql/main.zeek 264 267

   :Type: :zeek:type:`Conn::RemovalHook`



