:tocdepth: 3

base/bif/plugins/Bro_Modbus.events.bif.zeek
===========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================================== ======================================================================
:bro:id:`modbus_exception`: :bro:type:`event`                              Generated for any Modbus exception message.
:bro:id:`modbus_mask_write_register_request`: :bro:type:`event`            Generated for a Modbus mask write register request.
:bro:id:`modbus_mask_write_register_response`: :bro:type:`event`           Generated for a Modbus mask write register request.
:bro:id:`modbus_message`: :bro:type:`event`                                Generated for any Modbus message regardless if the particular function
                                                                           is further supported or not.
:bro:id:`modbus_read_coils_request`: :bro:type:`event`                     Generated for a Modbus read coils request.
:bro:id:`modbus_read_coils_response`: :bro:type:`event`                    Generated for a Modbus read coils response.
:bro:id:`modbus_read_discrete_inputs_request`: :bro:type:`event`           Generated for a Modbus read discrete inputs request.
:bro:id:`modbus_read_discrete_inputs_response`: :bro:type:`event`          Generated for a Modbus read discrete inputs response.
:bro:id:`modbus_read_fifo_queue_request`: :bro:type:`event`                Generated for a Modbus read FIFO queue request.
:bro:id:`modbus_read_fifo_queue_response`: :bro:type:`event`               Generated for a Modbus read FIFO queue response.
:bro:id:`modbus_read_file_record_request`: :bro:type:`event`               Generated for a Modbus read file record request.
:bro:id:`modbus_read_file_record_response`: :bro:type:`event`              Generated for a Modbus read file record response.
:bro:id:`modbus_read_holding_registers_request`: :bro:type:`event`         Generated for a Modbus read holding registers request.
:bro:id:`modbus_read_holding_registers_response`: :bro:type:`event`        Generated for a Modbus read holding registers response.
:bro:id:`modbus_read_input_registers_request`: :bro:type:`event`           Generated for a Modbus read input registers request.
:bro:id:`modbus_read_input_registers_response`: :bro:type:`event`          Generated for a Modbus read input registers response.
:bro:id:`modbus_read_write_multiple_registers_request`: :bro:type:`event`  Generated for a Modbus read/write multiple registers request.
:bro:id:`modbus_read_write_multiple_registers_response`: :bro:type:`event` Generated for a Modbus read/write multiple registers response.
:bro:id:`modbus_write_file_record_request`: :bro:type:`event`              Generated for a Modbus write file record request.
:bro:id:`modbus_write_file_record_response`: :bro:type:`event`             Generated for a Modbus write file record response.
:bro:id:`modbus_write_multiple_coils_request`: :bro:type:`event`           Generated for a Modbus write multiple coils request.
:bro:id:`modbus_write_multiple_coils_response`: :bro:type:`event`          Generated for a Modbus write multiple coils response.
:bro:id:`modbus_write_multiple_registers_request`: :bro:type:`event`       Generated for a Modbus write multiple registers request.
:bro:id:`modbus_write_multiple_registers_response`: :bro:type:`event`      Generated for a Modbus write multiple registers response.
:bro:id:`modbus_write_single_coil_request`: :bro:type:`event`              Generated for a Modbus write single coil request.
:bro:id:`modbus_write_single_coil_response`: :bro:type:`event`             Generated for a Modbus write single coil response.
:bro:id:`modbus_write_single_register_request`: :bro:type:`event`          Generated for a Modbus write single register request.
:bro:id:`modbus_write_single_register_response`: :bro:type:`event`         Generated for a Modbus write single register response.
========================================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: modbus_exception

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, code: :bro:type:`count`)

   Generated for any Modbus exception message.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :code: The exception code.

.. bro:id:: modbus_mask_write_register_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, address: :bro:type:`count`, and_mask: :bro:type:`count`, or_mask: :bro:type:`count`)

   Generated for a Modbus mask write register request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the register where the masks should be applied.
   

   :and_mask: The value of the logical AND mask to apply to the register.
   

   :or_mask: The value of the logical OR mask to apply to the register.

.. bro:id:: modbus_mask_write_register_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, address: :bro:type:`count`, and_mask: :bro:type:`count`, or_mask: :bro:type:`count`)

   Generated for a Modbus mask write register request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the register where the masks were applied.
   

   :and_mask: The value of the logical AND mask applied register.
   

   :or_mask: The value of the logical OR mask applied to the register.

.. bro:id:: modbus_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, is_orig: :bro:type:`bool`)

   Generated for any Modbus message regardless if the particular function
   is further supported or not.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :is_orig: True if the event is raised for the originator side.

.. bro:id:: modbus_read_coils_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, quantity: :bro:type:`count`)

   Generated for a Modbus read coils request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first coil to be read.
   

   :quantity: The number of coils to be read.

.. bro:id:: modbus_read_coils_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, coils: :bro:type:`ModbusCoils`)

   Generated for a Modbus read coils response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :coils: The coil values returned from the device.

.. bro:id:: modbus_read_discrete_inputs_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, quantity: :bro:type:`count`)

   Generated for a Modbus read discrete inputs request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first coil to be read.
   

   :quantity: The number of coils to be read.

.. bro:id:: modbus_read_discrete_inputs_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, coils: :bro:type:`ModbusCoils`)

   Generated for a Modbus read discrete inputs response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :coils: The coil values returned from the device.

.. bro:id:: modbus_read_fifo_queue_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`)

   Generated for a Modbus read FIFO queue request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The address of the FIFO queue to read.

.. bro:id:: modbus_read_fifo_queue_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, fifos: :bro:type:`ModbusRegisters`)

   Generated for a Modbus read FIFO queue response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :fifos: The register values read from the FIFO queue on the device.

.. bro:id:: modbus_read_file_record_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`)

   Generated for a Modbus read file record request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   
   .. note: This event is incomplete.  The information from the data structure
            is not yet passed through to the event.

.. bro:id:: modbus_read_file_record_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`)

   Generated for a Modbus read file record response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   
   .. note: This event is incomplete.  The information from the data structure
            is not yet passed through to the event.

.. bro:id:: modbus_read_holding_registers_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, quantity: :bro:type:`count`)

   Generated for a Modbus read holding registers request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first register to be read.
   

   :quantity: The number of registers to be read.

.. bro:id:: modbus_read_holding_registers_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, registers: :bro:type:`ModbusRegisters`)

   Generated for a Modbus read holding registers response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :registers: The register values returned from the device.

.. bro:id:: modbus_read_input_registers_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, quantity: :bro:type:`count`)

   Generated for a Modbus read input registers request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first register to be read.
   

   :quantity: The number of registers to be read.

.. bro:id:: modbus_read_input_registers_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, registers: :bro:type:`ModbusRegisters`)

   Generated for a Modbus read input registers response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :registers: The register values returned from the device.

.. bro:id:: modbus_read_write_multiple_registers_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, read_start_address: :bro:type:`count`, read_quantity: :bro:type:`count`, write_start_address: :bro:type:`count`, write_registers: :bro:type:`ModbusRegisters`)

   Generated for a Modbus read/write multiple registers request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :read_start_address: The memory address of the first register to be read.
   

   :read_quantity: The number of registers to read.
   

   :write_start_address: The memory address of the first register to be written.
   

   :write_registers: The values to be written to the registers.

.. bro:id:: modbus_read_write_multiple_registers_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, written_registers: :bro:type:`ModbusRegisters`)

   Generated for a Modbus read/write multiple registers response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :written_registers: The register values read from the registers specified in
                      the request.

.. bro:id:: modbus_write_file_record_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`)

   Generated for a Modbus write file record request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   
   .. note: This event is incomplete.  The information from the data structure
            is not yet passed through to the event.

.. bro:id:: modbus_write_file_record_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`)

   Generated for a Modbus write file record response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   
   .. note: This event is incomplete.  The information from the data structure
            is not yet passed through to the event.

.. bro:id:: modbus_write_multiple_coils_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, coils: :bro:type:`ModbusCoils`)

   Generated for a Modbus write multiple coils request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first coil to be written.
   

   :coils: The values to be written to the coils.

.. bro:id:: modbus_write_multiple_coils_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, quantity: :bro:type:`count`)

   Generated for a Modbus write multiple coils response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first coil that was written.
   

   :quantity: The quantity of coils that were written.

.. bro:id:: modbus_write_multiple_registers_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, registers: :bro:type:`ModbusRegisters`)

   Generated for a Modbus write multiple registers request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first register to be written.
   

   :registers: The values to be written to the registers.

.. bro:id:: modbus_write_multiple_registers_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, quantity: :bro:type:`count`)

   Generated for a Modbus write multiple registers response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first register that was written.
   

   :quantity: The quantity of registers that were written.

.. bro:id:: modbus_write_single_coil_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, address: :bro:type:`count`, value: :bro:type:`bool`)

   Generated for a Modbus write single coil request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the coil to be written.
   

   :value: The value to be written to the coil.

.. bro:id:: modbus_write_single_coil_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, address: :bro:type:`count`, value: :bro:type:`bool`)

   Generated for a Modbus write single coil response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the coil that was written.
   

   :value: The value that was written to the coil.

.. bro:id:: modbus_write_single_register_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, address: :bro:type:`count`, value: :bro:type:`count`)

   Generated for a Modbus write single register request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the register to be written.
   

   :value: The value to be written to the register.

.. bro:id:: modbus_write_single_register_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, address: :bro:type:`count`, value: :bro:type:`count`)

   Generated for a Modbus write single register response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the register that was written.
   

   :value: The value that was written to the register.


