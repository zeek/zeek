:tocdepth: 3

base/protocols/modbus/consts.zeek
=================================
.. zeek:namespace:: Modbus


:Namespace: Modbus

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================================================== =======================================
:zeek:id:`Modbus::exception_codes`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&redef` 
:zeek:id:`Modbus::function_codes`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&redef`  Standard defined Modbus function codes.
======================================================================================================================== =======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Modbus::exception_codes
   :source-code: base/protocols/modbus/consts.zeek 56 56

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&redef`
   :Default:

      ::

         {
            [2] = "ILLEGAL_DATA_ADDRESS",
            [8] = "MEMORY_PARITY_ERROR",
            [11] = "GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND",
            [5] = "ACKNOWLEDGE",
            [3] = "ILLEGAL_DATA_VALUE",
            [10] = "GATEWAY_PATH_UNAVAILABLE",
            [6] = "SLAVE_DEVICE_BUSY",
            [4] = "SLAVE_DEVICE_FAILURE",
            [1] = "ILLEGAL_FUNCTION"
         }



.. zeek:id:: Modbus::function_codes
   :source-code: base/protocols/modbus/consts.zeek 6 6

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&redef`
   :Default:

      ::

         {
            [40] = "PROGRAM_CONCEPT",
            [19] = "RESET_COMM_LINK_884_U84",
            [20] = "READ_FILE_RECORD",
            [149] = "WRITE_FILE_RECORD_EXCEPTION",
            [151] = "READ_WRITE_MULTIPLE_REGISTERS_EXCEPTION",
            [15] = "WRITE_MULTIPLE_COILS",
            [6] = "WRITE_SINGLE_REGISTER",
            [14] = "POLL_584_984",
            [125] = "FIRMWARE_REPLACEMENT",
            [8] = "DIAGNOSTICS",
            [23] = "READ_WRITE_MULTIPLE_REGISTERS",
            [9] = "PROGRAM_484",
            [7] = "READ_EXCEPTION_STATUS",
            [127] = "REPORT_LOCAL_ADDRESS",
            [21] = "WRITE_FILE_RECORD",
            [10] = "POLL_484",
            [4] = "READ_INPUT_REGISTERS",
            [13] = "PROGRAM_584_984",
            [12] = "GET_COMM_EVENT_LOG",
            [130] = "READ_DISCRETE_INPUTS_EXCEPTION",
            [148] = "READ_FILE_RECORD_EXCEPTION",
            [17] = "REPORT_SLAVE_ID",
            [134] = "WRITE_SINGLE_REGISTER_EXCEPTION",
            [152] = "READ_FIFO_QUEUE_EXCEPTION",
            [150] = "MASK_WRITE_REGISTER_EXCEPTION",
            [2] = "READ_DISCRETE_INPUTS",
            [132] = "READ_INPUT_REGISTERS_EXCEPTION",
            [16] = "WRITE_MULTIPLE_REGISTERS",
            [24] = "READ_FIFO_QUEUE",
            [133] = "WRITE_SINGLE_COIL_EXCEPTION",
            [1] = "READ_COILS",
            [11] = "GET_COMM_EVENT_COUNTER",
            [126] = "PROGRAM_584_984_2",
            [5] = "WRITE_SINGLE_COIL",
            [22] = "MASK_WRITE_REGISTER",
            [43] = "ENCAP_INTERFACE_TRANSPORT",
            [143] = "WRITE_MULTIPLE_COILS_EXCEPTION",
            [18] = "PROGRAM_884_U84",
            [135] = "READ_EXCEPTION_STATUS_EXCEPTION",
            [3] = "READ_HOLDING_REGISTERS",
            [131] = "READ_HOLDING_REGISTERS_EXCEPTION",
            [144] = "WRITE_MULTIPLE_REGISTERS_EXCEPTION",
            [129] = "READ_COILS_EXCEPTION"
         }


   Standard defined Modbus function codes.


