:tocdepth: 3

base/protocols/mysql/consts.bro
===============================
.. bro:namespace:: MySQL


:Namespace: MySQL

Summary
~~~~~~~
Constants
#########
============================================================================================================== =
:bro:id:`MySQL::commands`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional` 
============================================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. bro:id:: MySQL::commands

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional`
   :Default:

   ::

      {
         [2] = "init_db",
         [9] = "statistics",
         [17] = "change_user",
         [27] = "set_option",
         [6] = "drop_db",
         [11] = "connect",
         [14] = "ping",
         [4] = "field_list",
         [22] = "stmt_prepare",
         [24] = "stmt_send_long_data",
         [30] = "binlog_dump_gtid",
         [1] = "quit",
         [8] = "shutdown",
         [7] = "refresh",
         [15] = "time",
         [23] = "stmt_execute",
         [29] = "daemon",
         [5] = "create_db",
         [25] = "stmt_close",
         [19] = "table_dump",
         [28] = "stmt_fetch",
         [31] = "reset_connection",
         [10] = "process_info",
         [0] = "sleep",
         [3] = "query",
         [12] = "process_kill",
         [13] = "debug",
         [18] = "binlog_dump",
         [21] = "register_slave",
         [16] = "delayed_insert",
         [20] = "connect_out",
         [26] = "stmt_reset"
      }



