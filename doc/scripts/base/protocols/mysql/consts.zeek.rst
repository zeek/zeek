:tocdepth: 3

base/protocols/mysql/consts.zeek
================================
.. zeek:namespace:: MySQL


:Namespace: MySQL

Summary
~~~~~~~
Constants
#########
============================================================================================ =
:zeek:id:`MySQL::commands`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` 
============================================================================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: MySQL::commands
   :source-code: base/protocols/mysql/consts.zeek 4 4

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [19] = "table_dump",
            [20] = "connect_out",
            [14] = "ping",
            [15] = "time",
            [6] = "drop_db",
            [30] = "binlog_dump_gtid",
            [31] = "reset_connection",
            [28] = "stmt_fetch",
            [23] = "stmt_execute",
            [8] = "shutdown",
            [27] = "set_option",
            [9] = "statistics",
            [7] = "refresh",
            [10] = "process_info",
            [21] = "register_slave",
            [4] = "field_list",
            [26] = "stmt_reset",
            [13] = "debug",
            [12] = "process_kill",
            [17] = "change_user",
            [25] = "stmt_close",
            [2] = "init_db",
            [29] = "daemon",
            [16] = "delayed_insert",
            [24] = "stmt_send_long_data",
            [1] = "quit",
            [11] = "connect",
            [5] = "create_db",
            [22] = "stmt_prepare",
            [18] = "binlog_dump",
            [3] = "query",
            [0] = "sleep"
         }




