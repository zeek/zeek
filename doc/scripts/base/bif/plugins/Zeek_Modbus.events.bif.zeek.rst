:tocdepth: 3

base/bif/plugins/Zeek_Modbus.events.bif.zeek
============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================================ ======================================================================
:zeek:id:`modbus_diagnostics_request`: :zeek:type:`event`                    Generated for a Modbus Diagnostics request.
:zeek:id:`modbus_diagnostics_response`: :zeek:type:`event`                   Generated for a Modbus Diagnostics response.
:zeek:id:`modbus_encap_interface_transport_request`: :zeek:type:`event`      Generated for a Modbus Encapsulated Interface Transport request.
:zeek:id:`modbus_encap_interface_transport_response`: :zeek:type:`event`     Generated for a Modbus Encapsulated Interface Transport response.
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
.. zeek:id:: modbus_diagnostics_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 341 341

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, subfunction: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for a Modbus Diagnostics request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param subfunction: The subfunction for the diagnostics request.
   

   :param data: The data passed in the diagnostics request.

.. zeek:id:: modbus_diagnostics_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 353 353

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, subfunction: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for a Modbus Diagnostics response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param subfunction: The subfunction for the diagnostics response.
   

   :param data: The data passed in the diagnostics response.

.. zeek:id:: modbus_encap_interface_transport_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 365 365

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, mei_type: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for a Modbus Encapsulated Interface Transport request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param mei_type: The MEI type for the request.
   

   :param data: The MEI type specific data passed in the request.

.. zeek:id:: modbus_encap_interface_transport_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 377 377

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, mei_type: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for a Modbus Encapsulated Interface Transport response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param mei_type: The MEI type for the response.
   

   :param data: The MEI type specific data passed in the response.

.. zeek:id:: modbus_exception
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 22 22

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, code: :zeek:type:`count`)

   Generated for any Modbus exception message.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param code: The exception code.

.. zeek:id:: modbus_mask_write_register_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 268 268

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, and_mask: :zeek:type:`count`, or_mask: :zeek:type:`count`)

   Generated for a Modbus mask write register request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param address: The memory address of the register where the masks should be applied.
   

   :param and_mask: The value of the logical AND mask to apply to the register.
   

   :param or_mask: The value of the logical OR mask to apply to the register.

.. zeek:id:: modbus_mask_write_register_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 282 282

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, and_mask: :zeek:type:`count`, or_mask: :zeek:type:`count`)

   Generated for a Modbus mask write register request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param address: The memory address of the register where the masks were applied.
   

   :param and_mask: The value of the logical AND mask applied register.
   

   :param or_mask: The value of the logical OR mask applied to the register.

.. zeek:id:: modbus_message
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 12 12

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, is_orig: :zeek:type:`bool`)

   Generated for any Modbus message regardless if the particular function
   is further supported or not.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param is_orig: True if the event is raised for the originator side.

.. zeek:id:: modbus_read_coils_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 34 34

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus read coils request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first coil to be read.
   

   :param quantity: The number of coils to be read.

.. zeek:id:: modbus_read_coils_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 44 44

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, coils: :zeek:type:`ModbusCoils`)

   Generated for a Modbus read coils response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param coils: The coil values returned from the device.

.. zeek:id:: modbus_read_discrete_inputs_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 56 56

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus read discrete inputs request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first coil to be read.
   

   :param quantity: The number of coils to be read.

.. zeek:id:: modbus_read_discrete_inputs_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 66 66

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, coils: :zeek:type:`ModbusCoils`)

   Generated for a Modbus read discrete inputs response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param coils: The coil values returned from the device.

.. zeek:id:: modbus_read_fifo_queue_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 319 319

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`)

   Generated for a Modbus read FIFO queue request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The address of the FIFO queue to read.

.. zeek:id:: modbus_read_fifo_queue_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 329 329

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, fifos: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus read FIFO queue response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param fifos: The register values read from the FIFO queue on the device.

.. zeek:id:: modbus_read_file_record_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 218 218

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, byte_count: :zeek:type:`count`, refs: :zeek:type:`ModbusFileRecordRequests`)

   Generated for a Modbus read file record request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param byte_count: The full byte count for all of the reference records that follow.
   

   :param refs: A vector of reference records.

.. zeek:id:: modbus_read_file_record_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 230 230

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, byte_count: :zeek:type:`count`, refs: :zeek:type:`ModbusFileRecordResponses`)

   Generated for a Modbus read file record response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param byte_count: The full byte count for all of the reference records that follow.
   

   :param refs: A vector of reference records.

.. zeek:id:: modbus_read_holding_registers_request
   :source-code: policy/protocols/modbus/track-memmap.zeek 62 65

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus read holding registers request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first register to be read.
   

   :param quantity: The number of registers to be read.

.. zeek:id:: modbus_read_holding_registers_response
   :source-code: policy/protocols/modbus/track-memmap.zeek 67 101

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, registers: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus read holding registers response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param registers: The register values returned from the device.

.. zeek:id:: modbus_read_input_registers_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 100 100

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus read input registers request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first register to be read.
   

   :param quantity: The number of registers to be read.

.. zeek:id:: modbus_read_input_registers_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 110 110

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, registers: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus read input registers response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param registers: The register values returned from the device.

.. zeek:id:: modbus_read_write_multiple_registers_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 298 298

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, read_start_address: :zeek:type:`count`, read_quantity: :zeek:type:`count`, write_start_address: :zeek:type:`count`, write_registers: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus read/write multiple registers request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param read_start_address: The memory address of the first register to be read.
   

   :param read_quantity: The number of registers to read.
   

   :param write_start_address: The memory address of the first register to be written.
   

   :param write_registers: The values to be written to the registers.

.. zeek:id:: modbus_read_write_multiple_registers_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 309 309

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, written_registers: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus read/write multiple registers response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param written_registers: The register values read from the registers specified in
                      the request.

.. zeek:id:: modbus_write_file_record_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 242 242

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, byte_count: :zeek:type:`count`, refs: :zeek:type:`ModbusFileReferences`)

   Generated for a Modbus write file record request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param byte_count: The full byte count for all of the reference records that follow.
   

   :param refs: A vector of reference records.

.. zeek:id:: modbus_write_file_record_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 254 254

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, byte_count: :zeek:type:`count`, refs: :zeek:type:`ModbusFileReferences`)

   Generated for a Modbus write file record response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param byte_count: The full byte count for all of the reference records that follow.
   

   :param refs: A vector of reference records.

.. zeek:id:: modbus_write_multiple_coils_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 170 170

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, coils: :zeek:type:`ModbusCoils`)

   Generated for a Modbus write multiple coils request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first coil to be written.
   

   :param coils: The values to be written to the coils.

.. zeek:id:: modbus_write_multiple_coils_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 182 182

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus write multiple coils response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first coil that was written.
   

   :param quantity: The quantity of coils that were written.

.. zeek:id:: modbus_write_multiple_registers_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 194 194

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, registers: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus write multiple registers request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first register to be written.
   

   :param registers: The values to be written to the registers.

.. zeek:id:: modbus_write_multiple_registers_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 206 206

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus write multiple registers response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first register that was written.
   

   :param quantity: The quantity of registers that were written.

.. zeek:id:: modbus_write_single_coil_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 122 122

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, value: :zeek:type:`bool`)

   Generated for a Modbus write single coil request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param address: The memory address of the coil to be written.
   

   :param value: The value to be written to the coil.

.. zeek:id:: modbus_write_single_coil_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 134 134

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, value: :zeek:type:`bool`)

   Generated for a Modbus write single coil response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param address: The memory address of the coil that was written.
   

   :param value: The value that was written to the coil.

.. zeek:id:: modbus_write_single_register_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 146 146

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for a Modbus write single register request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param address: The memory address of the register to be written.
   

   :param value: The value to be written to the register.

.. zeek:id:: modbus_write_single_register_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 158 158

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for a Modbus write single register response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param address: The memory address of the register that was written.
   

   :param value: The value that was written to the register.


