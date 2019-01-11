:tocdepth: 3

base/protocols/modbus/consts.bro
================================
.. bro:namespace:: Modbus


:Namespace: Modbus

Summary
~~~~~~~
Redefinable Options
###################
========================================================================================================================================= =======================================
:bro:id:`Modbus::exception_codes`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional` :bro:attr:`&redef` 
:bro:id:`Modbus::function_codes`: :bro:type:`table` :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional` :bro:attr:`&redef`  Standard defined Modbus function codes.
========================================================================================================================================= =======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: Modbus::exception_codes

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional` :bro:attr:`&redef`
   :Default:

   ::

      {
         [2] = "ILLEGAL_DATA_ADDRESS",
         [6] = "SLAVE_DEVICE_BUSY",
         [11] = "GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND",
         [4] = "SLAVE_DEVICE_FAILURE",
         [1] = "ILLEGAL_FUNCTION",
         [8] = "MEMORY_PARITY_ERROR",
         [5] = "ACKNOWLEDGE",
         [10] = "GATEWAY_PATH_UNAVAILABLE",
         [3] = "ILLEGAL_DATA_VALUE"
      }


.. bro:id:: Modbus::function_codes

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string`
   :Attributes: :bro:attr:`&default` = :bro:type:`function` :bro:attr:`&optional` :bro:attr:`&redef`
   :Default:

   ::

      {
         [2] = "READ_DISCRETE_INPUTS",
         [17] = "REPORT_SLAVE_ID",
         [9] = "PROGRAM_484",
         [126] = "PROGRAM_584_984_2",
         [143] = "WRITE_MULTIPLE_COILS_EXCEPTION",
         [152] = "READ_FIFO_QUEUE_EXCEPTION",
         [6] = "WRITE_SINGLE_REGISTER",
         [11] = "GET_COMM_EVENT_COUNTER",
         [14] = "POLL_584_984",
         [4] = "READ_INPUT_REGISTERS",
         [22] = "MASK_WRITE_REGISTER",
         [24] = "READ_FIFO_QUEUE",
         [144] = "WRITE_MULTIPLE_REGISTERS_EXCEPTION",
         [1] = "READ_COILS",
         [8] = "DIAGNOSTICS",
         [7] = "READ_EXCEPTION_STATUS",
         [15] = "WRITE_MULTIPLE_COILS",
         [131] = "READ_HOLDING_REGISTERS_EXCEPTION",
         [23] = "READ_WRITE_MULTIPLE_REGISTERS",
         [43] = "ENCAP_INTERFACE_TRANSPORT",
         [127] = "REPORT_LOCAL_ADDRESS",
         [133] = "WRITE_SINGLE_COIL_EXCEPTION",
         [134] = "WRITE_SINGLE_REGISTER_EXCEPTION",
         [130] = "READ_DISCRETE_INPUTS_EXCEPTION",
         [149] = "WRITE_FILE_RECORD_EXCEPTION",
         [5] = "WRITE_SINGLE_COIL",
         [19] = "RESET_COMM_LINK_884_U84",
         [125] = "FIRMWARE_REPLACEMENT",
         [132] = "READ_INPUT_REGISTERS_EXCEPTION",
         [10] = "POLL_484",
         [129] = "READ_COILS_EXCEPTION",
         [150] = "MASK_WRITE_REGISTER_EXCEPTION",
         [3] = "READ_HOLDING_REGISTERS",
         [12] = "GET_COMM_EVENT_LOG",
         [21] = "WRITE_FILE_RECORD",
         [13] = "PROGRAM_584_984",
         [18] = "PROGRAM_884_U84",
         [148] = "READ_FILE_RECORD_EXCEPTION",
         [151] = "READ_WRITE_MULTIPLE_REGISTERS_EXCEPTION",
         [16] = "WRITE_MULTIPLE_REGISTERS",
         [20] = "READ_FILE_RECORD",
         [40] = "PROGRAM_CONCEPT",
         [135] = "READ_EXCEPTION_STATUS_EXCEPTION"
      }

   Standard defined Modbus function codes.


