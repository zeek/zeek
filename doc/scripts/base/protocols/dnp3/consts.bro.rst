:tocdepth: 3

base/protocols/dnp3/consts.bro
==============================
.. bro:namespace:: DNP3


:Namespace: DNP3

Summary
~~~~~~~
Redefinable Options
###################
====================================================================================================================================== =======================================
:bro:id:`DNP3::function_codes`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional` :bro:attr:`&redef` Standard defined Modbus function codes.
====================================================================================================================================== =======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: DNP3::function_codes

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional` :bro:attr:`&redef`
   :Default:

   ::

      {
         [2] = "WRITE",
         [9] = "FREEZE_CLEAR",
         [17] = "START_APPL",
         [27] = "DELETE_FILE",
         [6] = "DIRECT_OPERATE_NR",
         [11] = "FREEZE_AT_TIME",
         [14] = "WARM_RESTART",
         [4] = "OPERATE",
         [22] = "ASSIGN_CLASS",
         [24] = "RECORD_CURRENT_TIME",
         [30] = "ABORT_FILE",
         [1] = "READ",
         [8] = "IMMED_FREEZE_NR",
         [7] = "IMMED_FREEZE",
         [15] = "INITIALIZE_DATA",
         [131] = "AUTHENTICATE_RESP",
         [23] = "DELAY_MEASURE",
         [33] = "AUTHENTICATE_REQ_NR",
         [29] = "AUTHENTICATE_FILE",
         [130] = "UNSOLICITED_RESPONSE",
         [5] = "DIRECT_OPERATE",
         [25] = "OPEN_FILE",
         [32] = "AUTHENTICATE_REQ",
         [19] = "SAVE_CONFIG",
         [28] = "GET_FILE_INFO",
         [31] = "ACTIVATE_CONFIG",
         [10] = "FREEZE_CLEAR_NR",
         [129] = "RESPONSE",
         [0] = "CONFIRM",
         [3] = "SELECT",
         [12] = "FREEZE_AT_TIME_NR",
         [13] = "COLD_RESTART",
         [18] = "STOP_APPL",
         [21] = "DISABLE_UNSOLICITED",
         [16] = "INITIALIZE_APPL",
         [20] = "ENABLE_UNSOLICITED",
         [26] = "CLOSE_FILE"
      }

   Standard defined Modbus function codes.


