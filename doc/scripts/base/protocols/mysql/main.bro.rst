:tocdepth: 3

base/protocols/mysql/main.bro
=============================
.. bro:namespace:: MySQL

Implements base functionality for MySQL analysis. Generates the mysql.log file.

:Namespace: MySQL
:Imports: :doc:`base/protocols/mysql/consts.bro </scripts/base/protocols/mysql/consts.bro>`

Summary
~~~~~~~
Types
#####
=========================================== =
:bro:type:`MySQL::Info`: :bro:type:`record` 
=========================================== =

Redefinitions
#############
========================================== =
:bro:type:`Log::ID`: :bro:type:`enum`      
:bro:type:`connection`: :bro:type:`record` 
========================================== =

Events
######
============================================= =====================================================================
:bro:id:`MySQL::log_mysql`: :bro:type:`event` Event that can be handled to access the MySQL record as it is sent on
                                              to the logging framework.
============================================= =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: MySQL::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp for when the event happened.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      cmd: :bro:type:`string` :bro:attr:`&log`
         The command that was issued

      arg: :bro:type:`string` :bro:attr:`&log`
         The argument issued to the command

      success: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&optional`
         Did the server tell us that the command succeeded?

      rows: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         The number of affected rows, if any

      response: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Server message, if any


Events
######
.. bro:id:: MySQL::log_mysql

   :Type: :bro:type:`event` (rec: :bro:type:`MySQL::Info`)

   Event that can be handled to access the MySQL record as it is sent on
   to the logging framework.


