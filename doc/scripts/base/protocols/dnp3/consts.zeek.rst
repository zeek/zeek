:tocdepth: 3

base/protocols/dnp3/consts.zeek
===============================
.. zeek:namespace:: DNP3


:Namespace: DNP3

Summary
~~~~~~~
Redefinable Options
###################
===================================================================================================================== =======================================
:zeek:id:`DNP3::function_codes`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&redef` Standard defined Modbus function codes.
===================================================================================================================== =======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: DNP3::function_codes
   :source-code: base/protocols/dnp3/consts.zeek 6 6

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&redef`
   :Default:

      ::

         {
            [19] = "SAVE_CONFIG",
            [20] = "ENABLE_UNSOLICITED",
            [33] = "AUTHENTICATE_REQ_NR",
            [14] = "WARM_RESTART",
            [15] = "INITIALIZE_DATA",
            [6] = "DIRECT_OPERATE_NR",
            [30] = "ABORT_FILE",
            [31] = "ACTIVATE_CONFIG",
            [28] = "GET_FILE_INFO",
            [23] = "DELAY_MEASURE",
            [8] = "IMMED_FREEZE_NR",
            [27] = "DELETE_FILE",
            [9] = "FREEZE_CLEAR",
            [7] = "IMMED_FREEZE",
            [10] = "FREEZE_CLEAR_NR",
            [21] = "DISABLE_UNSOLICITED",
            [4] = "OPERATE",
            [26] = "CLOSE_FILE",
            [13] = "COLD_RESTART",
            [12] = "FREEZE_AT_TIME_NR",
            [32] = "AUTHENTICATE_REQ",
            [130] = "UNSOLICITED_RESPONSE",
            [17] = "START_APPL",
            [25] = "OPEN_FILE",
            [2] = "WRITE",
            [29] = "AUTHENTICATE_FILE",
            [16] = "INITIALIZE_APPL",
            [24] = "RECORD_CURRENT_TIME",
            [1] = "READ",
            [11] = "FREEZE_AT_TIME",
            [5] = "DIRECT_OPERATE",
            [22] = "ASSIGN_CLASS",
            [18] = "STOP_APPL",
            [3] = "SELECT",
            [0] = "CONFIRM",
            [131] = "AUTHENTICATE_RESP",
            [129] = "RESPONSE"
         }


   Standard defined Modbus function codes.


