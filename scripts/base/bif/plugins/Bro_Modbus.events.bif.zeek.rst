:tocdepth: 3

base/bif/plugins/Bro_Modbus.events.bif.zeek
===========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================================ ======================================================================
:zeek:id:`modbus_exception`: :zeek:type:`event`                              Generated for any Modbus exception message.
:zeek:id:`modbus_mask_write_register_request`: :zeek:type:`event`            Generated for a Modbus mask write register request.
:zeek:id:`modbus_mask_write_register_response`: :zeek:type:`event`           Generated for a Modbus mask write register request.
:zeek:id:`modbus_message`: :zeek:type:`event`                                Generated for any Modbus message regardless if the particular function
                                                                             is further supported or not.
:zeek:id:`modbus_read_coils_request`: :zeek:type:`event`                     Generated for a Modbus read coils request.
:zeek:id:`modbus_read_coils_response`: :zeek:type:`event`                    Generated for a Modbus read coils response.
:zeek:id:`modbus_read_discrete_inputs_request`: :zeek:type:`event`           Generated for a Modbus read discrete inputs request.
:zeek:id:`modbus_read_discrete_inputs_response`: :zeek:type:`event`          Generated for a Modbus read discrete inputs response.
:zeek:id:`modbus_read_fifo_queue_request`: :zeek:type:`event`                Generated for a Modbus read FIFO queue request.
:zeek:id:`modbus_read_fifo_queue_response`: :zeek:type:`event`               Generated for a Modbus read FIFO queue response.
:zeek:id:`modbus_read_file_record_request`: :zeek:type:`event`               Generated for a Modbus read file record request.
:zeek:id:`modbus_read_file_record_response`: :zeek:type:`event`              Generated for a Modbus read file record response.
:zeek:id:`modbus_read_holding_registers_request`: :zeek:type:`event`         Generated for a Modbus read holding registers request.
:zeek:id:`modbus_read_holding_registers_response`: :zeek:type:`event`        Generated for a Modbus read holding registers response.
:zeek:id:`modbus_read_input_registers_request`: :zeek:type:`event`           Generated for a Modbus read input registers request.
:zeek:id:`modbus_read_input_registers_response`: :zeek:type:`event`          Generated for a Modbus read input registers response.
:zeek:id:`modbus_read_write_multiple_registers_request`: :zeek:type:`event`  Generated for a Modbus read/write multiple registers request.
:zeek:id:`modbus_read_write_multiple_registers_response`: :zeek:type:`event` Generated for a Modbus read/write multiple registers response.
:zeek:id:`modbus_write_file_record_request`: :zeek:type:`event`              Generated for a Modbus write file record request.
:zeek:id:`modbus_write_file_record_response`: :zeek:type:`event`             Generated for a Modbus write file record response.
:zeek:id:`modbus_write_multiple_coils_request`: :zeek:type:`event`           Generated for a Modbus write multiple coils request.
:zeek:id:`modbus_write_multiple_coils_response`: :zeek:type:`event`          Generated for a Modbus write multiple coils response.
:zeek:id:`modbus_write_multiple_registers_request`: :zeek:type:`event`       Generated for a Modbus write multiple registers request.
:zeek:id:`modbus_write_multiple_registers_response`: :zeek:type:`event`      Generated for a Modbus write multiple registers response.
:zeek:id:`modbus_write_single_coil_request`: :zeek:type:`event`              Generated for a Modbus write single coil request.
:zeek:id:`modbus_write_single_coil_response`: :zeek:type:`event`             Generated for a Modbus write single coil response.
:zeek:id:`modbus_write_single_register_request`: :zeek:type:`event`          Generated for a Modbus write single register request.
:zeek:id:`modbus_write_single_register_response`: :zeek:type:`event`         Generated for a Modbus write single register response.
============================================================================ ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: modbus_exception

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, code: :zeek:type:`count`)

   Generated for any Modbus exception message.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :code: The exception code.

.. zeek:id:: modbus_mask_write_register_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, and_mask: :zeek:type:`count`, or_mask: :zeek:type:`count`)

   Generated for a Modbus mask write register request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the register where the masks should be applied.
   

   :and_mask: The value of the logical AND mask to apply to the register.
   

   :or_mask: The value of the logical OR mask to apply to the register.

.. zeek:id:: modbus_mask_write_register_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, and_mask: :zeek:type:`count`, or_mask: :zeek:type:`count`)

   Generated for a Modbus mask write register request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the register where the masks were applied.
   

   :and_mask: The value of the logical AND mask applied register.
   

   :or_mask: The value of the logical OR mask applied to the register.

.. zeek:id:: modbus_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, is_orig: :zeek:type:`bool`)

   Generated for any Modbus message regardless if the particular function
   is further supported or not.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :is_orig: True if the event is raised for the originator side.

.. zeek:id:: modbus_read_coils_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus read coils request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first coil to be read.
   

   :quantity: The number of coils to be read.

.. zeek:id:: modbus_read_coils_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, coils: :zeek:type:`ModbusCoils`)

   Generated for a Modbus read coils response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :coils: The coil values returned from the device.

.. zeek:id:: modbus_read_discrete_inputs_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus read discrete inputs request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first coil to be read.
   

   :quantity: The number of coils to be read.

.. zeek:id:: modbus_read_discrete_inputs_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, coils: :zeek:type:`ModbusCoils`)

   Generated for a Modbus read discrete inputs response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :coils: The coil values returned from the device.

.. zeek:id:: modbus_read_fifo_queue_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`)

   Generated for a Modbus read FIFO queue request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The address of the FIFO queue to read.

.. zeek:id:: modbus_read_fifo_queue_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, fifos: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus read FIFO queue response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :fifos: The register values read from the FIFO queue on the device.

.. zeek:id:: modbus_read_file_record_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`)

   Generated for a Modbus read file record request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   
   .. note: This event is incomplete.  The information from the data structure
            is not yet passed through to the event.

.. zeek:id:: modbus_read_file_record_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`)

   Generated for a Modbus read file record response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   
   .. note: This event is incomplete.  The information from the data structure
            is not yet passed through to the event.

.. zeek:id:: modbus_read_holding_registers_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus read holding registers request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first register to be read.
   

   :quantity: The number of registers to be read.

.. zeek:id:: modbus_read_holding_registers_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, registers: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus read holding registers response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :registers: The register values returned from the device.

.. zeek:id:: modbus_read_input_registers_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus read input registers request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first register to be read.
   

   :quantity: The number of registers to be read.

.. zeek:id:: modbus_read_input_registers_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, registers: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus read input registers response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :registers: The register values returned from the device.

.. zeek:id:: modbus_read_write_multiple_registers_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, read_start_address: :zeek:type:`count`, read_quantity: :zeek:type:`count`, write_start_address: :zeek:type:`count`, write_registers: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus read/write multiple registers request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :read_start_address: The memory address of the first register to be read.
   

   :read_quantity: The number of registers to read.
   

   :write_start_address: The memory address of the first register to be written.
   

   :write_registers: The values to be written to the registers.

.. zeek:id:: modbus_read_write_multiple_registers_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, written_registers: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus read/write multiple registers response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :written_registers: The register values read from the registers specified in
                      the request.

.. zeek:id:: modbus_write_file_record_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`)

   Generated for a Modbus write file record request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   
   .. note: This event is incomplete.  The information from the data structure
            is not yet passed through to the event.

.. zeek:id:: modbus_write_file_record_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`)

   Generated for a Modbus write file record response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   
   .. note: This event is incomplete.  The information from the data structure
            is not yet passed through to the event.

.. zeek:id:: modbus_write_multiple_coils_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, coils: :zeek:type:`ModbusCoils`)

   Generated for a Modbus write multiple coils request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first coil to be written.
   

   :coils: The values to be written to the coils.

.. zeek:id:: modbus_write_multiple_coils_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus write multiple coils response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first coil that was written.
   

   :quantity: The quantity of coils that were written.

.. zeek:id:: modbus_write_multiple_registers_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, registers: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus write multiple registers request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first register to be written.
   

   :registers: The values to be written to the registers.

.. zeek:id:: modbus_write_multiple_registers_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus write multiple registers response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first register that was written.
   

   :quantity: The quantity of registers that were written.

.. zeek:id:: modbus_write_single_coil_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, value: :zeek:type:`bool`)

   Generated for a Modbus write single coil request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the coil to be written.
   

   :value: The value to be written to the coil.

.. zeek:id:: modbus_write_single_coil_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, value: :zeek:type:`bool`)

   Generated for a Modbus write single coil response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the coil that was written.
   

   :value: The value that was written to the coil.

.. zeek:id:: modbus_write_single_register_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for a Modbus write single register request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the register to be written.
   

   :value: The value to be written to the register.

.. zeek:id:: modbus_write_single_register_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for a Modbus write single register response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the register that was written.
   

   :value: The value that was written to the register.


