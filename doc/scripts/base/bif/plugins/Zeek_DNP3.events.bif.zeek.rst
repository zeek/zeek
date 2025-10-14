:tocdepth: 3

base/bif/plugins/Zeek_DNP3.events.bif.zeek
==========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
====================================================================== ===========================================================================
:zeek:id:`dnp3_analog_input_16wFlag`: :zeek:type:`event`               Generated for DNP3 objects with the group number 30 and variation number 2
                                                                       analog input 16 bit with flag
:zeek:id:`dnp3_analog_input_16woFlag`: :zeek:type:`event`              Generated for DNP3 objects with the group number 30 and variation number 4
                                                                       analog input 16 bit without flag
:zeek:id:`dnp3_analog_input_32wFlag`: :zeek:type:`event`               Generated for DNP3 objects with the group number 30 and variation number 1
                                                                       analog input 32 bit with flag
:zeek:id:`dnp3_analog_input_32woFlag`: :zeek:type:`event`              Generated for DNP3 objects with the group number 30 and variation number 3
                                                                       analog input 32 bit without flag
:zeek:id:`dnp3_analog_input_DPwFlag`: :zeek:type:`event`               Generated for DNP3 objects with the group number 30 and variation number 6
                                                                       analog input double precision, float point with flag
:zeek:id:`dnp3_analog_input_SPwFlag`: :zeek:type:`event`               Generated for DNP3 objects with the group number 30 and variation number 5
                                                                       analog input single precision, float point with flag
:zeek:id:`dnp3_analog_input_event_16wTime`: :zeek:type:`event`         Generated for DNP3 objects with the group number 32 and variation number 4
                                                                       analog input event 16 bit with time
:zeek:id:`dnp3_analog_input_event_16woTime`: :zeek:type:`event`        Generated for DNP3 objects with the group number 32 and variation number 2
                                                                       analog input event 16 bit without time
:zeek:id:`dnp3_analog_input_event_32wTime`: :zeek:type:`event`         Generated for DNP3 objects with the group number 32 and variation number 3
                                                                       analog input event 32 bit with time
:zeek:id:`dnp3_analog_input_event_32woTime`: :zeek:type:`event`        Generated for DNP3 objects with the group number 32 and variation number 1
                                                                       analog input event 32 bit without time
:zeek:id:`dnp3_analog_input_event_DPwTime`: :zeek:type:`event`         Generated for DNP3 objects with the group number 32 and variation number 8
                                                                       analog input event double-precision float point with time
:zeek:id:`dnp3_analog_input_event_DPwoTime`: :zeek:type:`event`        Generated for DNP3 objects with the group number 32 and variation number 6
                                                                       analog input event double-precision float point without time
:zeek:id:`dnp3_analog_input_event_SPwTime`: :zeek:type:`event`         Generated for DNP3 objects with the group number 32 and variation number 7
                                                                       analog input event single-precision float point with time
:zeek:id:`dnp3_analog_input_event_SPwoTime`: :zeek:type:`event`        Generated for DNP3 objects with the group number 32 and variation number 5
                                                                       analog input event single-precision float point without time
:zeek:id:`dnp3_application_request_header`: :zeek:type:`event`         Generated for a DNP3 request header.
:zeek:id:`dnp3_application_response_header`: :zeek:type:`event`        Generated for a DNP3 response header.
:zeek:id:`dnp3_attribute_common`: :zeek:type:`event`                   Generated for DNP3 attributes.
:zeek:id:`dnp3_counter_16wFlag`: :zeek:type:`event`                    Generated for DNP3 objects with the group number 20 and variation number 2
                                                                       counter 16 bit with flag
:zeek:id:`dnp3_counter_16woFlag`: :zeek:type:`event`                   Generated for DNP3 objects with the group number 20 and variation number 6
                                                                       counter 16 bit without flag
:zeek:id:`dnp3_counter_32wFlag`: :zeek:type:`event`                    Generated for DNP3 objects with the group number 20 and variation number 1
                                                                       counter 32 bit with flag
:zeek:id:`dnp3_counter_32woFlag`: :zeek:type:`event`                   Generated for DNP3 objects with the group number 20 and variation number 5
                                                                       counter 32 bit without flag
:zeek:id:`dnp3_crob`: :zeek:type:`event`                               Generated for DNP3 objects with the group number 12 and variation number 1
                                                                       CROB: control relay output block
:zeek:id:`dnp3_debug_byte`: :zeek:type:`event`                         Debugging event generated by the DNP3 analyzer.
:zeek:id:`dnp3_file_transport`: :zeek:type:`event`                     g70
:zeek:id:`dnp3_frozen_analog_input_16wFlag`: :zeek:type:`event`        Generated for DNP3 objects with the group number 31 and variation number 2
                                                                       frozen analog input 16 bit with flag
:zeek:id:`dnp3_frozen_analog_input_16wTime`: :zeek:type:`event`        Generated for DNP3 objects with the group number 31 and variation number 4
                                                                       frozen analog input 16 bit with time-of-freeze
:zeek:id:`dnp3_frozen_analog_input_16woFlag`: :zeek:type:`event`       Generated for DNP3 objects with the group number 31 and variation number 6
                                                                       frozen analog input 16 bit without flag
:zeek:id:`dnp3_frozen_analog_input_32wFlag`: :zeek:type:`event`        Generated for DNP3 objects with the group number 31 and variation number 1
                                                                       frozen analog input 32 bit with flag
:zeek:id:`dnp3_frozen_analog_input_32wTime`: :zeek:type:`event`        Generated for DNP3 objects with the group number 31 and variation number 3
                                                                       frozen analog input 32 bit with time-of-freeze
:zeek:id:`dnp3_frozen_analog_input_32woFlag`: :zeek:type:`event`       Generated for DNP3 objects with the group number 31 and variation number 5
                                                                       frozen analog input 32 bit without flag
:zeek:id:`dnp3_frozen_analog_input_DPwFlag`: :zeek:type:`event`        Generated for DNP3 objects with the group number 31 and variation number 8
                                                                       frozen analog input double-precision, float point with flag
:zeek:id:`dnp3_frozen_analog_input_SPwFlag`: :zeek:type:`event`        Generated for DNP3 objects with the group number 31 and variation number 7
                                                                       frozen analog input single-precision, float point with flag
:zeek:id:`dnp3_frozen_analog_input_event_16wTime`: :zeek:type:`event`  Generated for DNP3 objects with the group number 33 and variation number 4
                                                                       frozen analog input event 16 bit with time
:zeek:id:`dnp3_frozen_analog_input_event_16woTime`: :zeek:type:`event` Generated for DNP3 objects with the group number 33 and variation number 2
                                                                       frozen analog input event 16 bit without time
:zeek:id:`dnp3_frozen_analog_input_event_32wTime`: :zeek:type:`event`  Generated for DNP3 objects with the group number 33 and variation number 3
                                                                       frozen analog input event 32 bit with time
:zeek:id:`dnp3_frozen_analog_input_event_32woTime`: :zeek:type:`event` Generated for DNP3 objects with the group number 33 and variation number 1
                                                                       frozen analog input event 32 bit without time
:zeek:id:`dnp3_frozen_analog_input_event_DPwTime`: :zeek:type:`event`  Generated for DNP3 objects with the group number 34 and variation number 8
                                                                       frozen analog input event double-precision float point with time
:zeek:id:`dnp3_frozen_analog_input_event_DPwoTime`: :zeek:type:`event` Generated for DNP3 objects with the group number 33 and variation number 6
                                                                       frozen analog input event double-precision float point without time
:zeek:id:`dnp3_frozen_analog_input_event_SPwTime`: :zeek:type:`event`  Generated for DNP3 objects with the group number 33 and variation number 7
                                                                       frozen analog input event single-precision float point with time
:zeek:id:`dnp3_frozen_analog_input_event_SPwoTime`: :zeek:type:`event` Generated for DNP3 objects with the group number 33 and variation number 5
                                                                       frozen analog input event single-precision float point without time
:zeek:id:`dnp3_frozen_counter_16wFlag`: :zeek:type:`event`             Generated for DNP3 objects with the group number 21 and variation number 2
                                                                       frozen counter 16 bit with flag
:zeek:id:`dnp3_frozen_counter_16wFlagTime`: :zeek:type:`event`         Generated for DNP3 objects with the group number 21 and variation number 6
                                                                       frozen counter 16 bit with flag and time
:zeek:id:`dnp3_frozen_counter_16woFlag`: :zeek:type:`event`            Generated for DNP3 objects with the group number 21 and variation number 10
                                                                       frozen counter 16 bit without flag
:zeek:id:`dnp3_frozen_counter_32wFlag`: :zeek:type:`event`             Generated for DNP3 objects with the group number 21 and variation number 1
                                                                       frozen counter 32 bit with flag
:zeek:id:`dnp3_frozen_counter_32wFlagTime`: :zeek:type:`event`         Generated for DNP3 objects with the group number 21 and variation number 5
                                                                       frozen counter 32 bit with flag and time
:zeek:id:`dnp3_frozen_counter_32woFlag`: :zeek:type:`event`            Generated for DNP3 objects with the group number 21 and variation number 9
                                                                       frozen counter 32 bit without flag
:zeek:id:`dnp3_header_block`: :zeek:type:`event`                       Generated for an additional header that the DNP3 analyzer passes to the
                                                                       script-level.
:zeek:id:`dnp3_object_header`: :zeek:type:`event`                      Generated for the object header found in both DNP3 requests and responses.
:zeek:id:`dnp3_object_prefix`: :zeek:type:`event`                      Generated for the prefix before a DNP3 object.
:zeek:id:`dnp3_pcb`: :zeek:type:`event`                                Generated for DNP3 objects with the group number 12 and variation number 2
                                                                       PCB: Pattern Control Block
:zeek:id:`dnp3_response_data_object`: :zeek:type:`event`               Generated for a DNP3 "Response_Data_Object".
====================================================================== ===========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: dnp3_analog_input_16wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 173 173

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 2
   analog input 16 bit with flag

.. zeek:id:: dnp3_analog_input_16woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 183 183

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 4
   analog input 16 bit without flag

.. zeek:id:: dnp3_analog_input_32wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 168 168

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 1
   analog input 32 bit with flag

.. zeek:id:: dnp3_analog_input_32woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 178 178

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 3
   analog input 32 bit without flag

.. zeek:id:: dnp3_analog_input_DPwFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 193 193

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value_low: :zeek:type:`count`, value_high: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 6
   analog input double precision, float point with flag

.. zeek:id:: dnp3_analog_input_SPwFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 188 188

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 5
   analog input single precision, float point with flag

.. zeek:id:: dnp3_analog_input_event_16wTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 253 253

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 4
   analog input event 16 bit with time

.. zeek:id:: dnp3_analog_input_event_16woTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 243 243

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 2
   analog input event 16 bit without time

.. zeek:id:: dnp3_analog_input_event_32wTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 248 248

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 3
   analog input event 32 bit with time

.. zeek:id:: dnp3_analog_input_event_32woTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 238 238

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 1
   analog input event 32 bit without time

.. zeek:id:: dnp3_analog_input_event_DPwTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 273 273

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value_low: :zeek:type:`count`, value_high: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 8
   analog input event double-precision float point with time

.. zeek:id:: dnp3_analog_input_event_DPwoTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 263 263

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value_low: :zeek:type:`count`, value_high: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 6
   analog input event double-precision float point without time

.. zeek:id:: dnp3_analog_input_event_SPwTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 268 268

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 7
   analog input event single-precision float point with time

.. zeek:id:: dnp3_analog_input_event_SPwoTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 258 258

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 5
   analog input event single-precision float point without time

.. zeek:id:: dnp3_application_request_header
   :source-code: base/protocols/dnp3/main.zeek 49 59

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, application: :zeek:type:`count`, fc: :zeek:type:`count`)

   Generated for a DNP3 request header.
   

   :param c: The connection the DNP3 communication is part of.
   

   :param is_orig: True if this reflects originator-side activity.
   

   :param fc: function code.
   

.. zeek:id:: dnp3_application_response_header
   :source-code: base/protocols/dnp3/main.zeek 61 76

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, application: :zeek:type:`count`, fc: :zeek:type:`count`, iin: :zeek:type:`count`)

   Generated for a DNP3 response header.
   

   :param c: The connection the DNP3 communication is part of.
   

   :param is_orig: True if this reflects originator-side activity.
   

   :param fc: function code.
   

   :param iin: internal indication number.
   

.. zeek:id:: dnp3_attribute_common
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 103 103

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, data_type_code: :zeek:type:`count`, leng: :zeek:type:`count`, attribute_obj: :zeek:type:`string`)

   Generated for DNP3 attributes.

.. zeek:id:: dnp3_counter_16wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 123 123

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 2
   counter 16 bit with flag

.. zeek:id:: dnp3_counter_16woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 133 133

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 6
   counter 16 bit without flag

.. zeek:id:: dnp3_counter_32wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 118 118

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 1
   counter 32 bit with flag

.. zeek:id:: dnp3_counter_32woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 128 128

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 5
   counter 32 bit without flag

.. zeek:id:: dnp3_crob
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 108 108

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, control_code: :zeek:type:`count`, count8: :zeek:type:`count`, on_time: :zeek:type:`count`, off_time: :zeek:type:`count`, status_code: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 12 and variation number 1

   :param CROB: control relay output block

.. zeek:id:: dnp3_debug_byte
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 323 323

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, debug: :zeek:type:`string`)

   Debugging event generated by the DNP3 analyzer. The "Debug_Byte" binpac unit
   generates this for unknown "cases". The user can use it to debug the byte
   string to check what caused the malformed network packets.

.. zeek:id:: dnp3_file_transport
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 317 317

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, file_handle: :zeek:type:`count`, block_num: :zeek:type:`count`, file_data: :zeek:type:`string`)

   g70

.. zeek:id:: dnp3_frozen_analog_input_16wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 203 203

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 2
   frozen analog input 16 bit with flag

.. zeek:id:: dnp3_frozen_analog_input_16wTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 213 213

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 4
   frozen analog input 16 bit with time-of-freeze

.. zeek:id:: dnp3_frozen_analog_input_16woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 223 223

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 6
   frozen analog input 16 bit without flag

.. zeek:id:: dnp3_frozen_analog_input_32wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 198 198

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 1
   frozen analog input 32 bit with flag

.. zeek:id:: dnp3_frozen_analog_input_32wTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 208 208

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 3
   frozen analog input 32 bit with time-of-freeze

.. zeek:id:: dnp3_frozen_analog_input_32woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 218 218

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 5
   frozen analog input 32 bit without flag

.. zeek:id:: dnp3_frozen_analog_input_DPwFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 233 233

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value_low: :zeek:type:`count`, frozen_value_high: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 8
   frozen analog input double-precision, float point with flag

.. zeek:id:: dnp3_frozen_analog_input_SPwFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 228 228

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 7
   frozen analog input single-precision, float point with flag

.. zeek:id:: dnp3_frozen_analog_input_event_16wTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 293 293

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 4
   frozen analog input event 16 bit with time

.. zeek:id:: dnp3_frozen_analog_input_event_16woTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 283 283

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 2
   frozen analog input event 16 bit without time

.. zeek:id:: dnp3_frozen_analog_input_event_32wTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 288 288

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 3
   frozen analog input event 32 bit with time

.. zeek:id:: dnp3_frozen_analog_input_event_32woTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 278 278

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 1
   frozen analog input event 32 bit without time

.. zeek:id:: dnp3_frozen_analog_input_event_DPwTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 313 313

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value_low: :zeek:type:`count`, frozen_value_high: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 34 and variation number 8
   frozen analog input event double-precision float point with time

.. zeek:id:: dnp3_frozen_analog_input_event_DPwoTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 303 303

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value_low: :zeek:type:`count`, frozen_value_high: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 6
   frozen analog input event double-precision float point without time

.. zeek:id:: dnp3_frozen_analog_input_event_SPwTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 308 308

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 7
   frozen analog input event single-precision float point with time

.. zeek:id:: dnp3_frozen_analog_input_event_SPwoTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 298 298

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 5
   frozen analog input event single-precision float point without time

.. zeek:id:: dnp3_frozen_counter_16wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 143 143

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 2
   frozen counter 16 bit with flag

.. zeek:id:: dnp3_frozen_counter_16wFlagTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 153 153

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 6
   frozen counter 16 bit with flag and time

.. zeek:id:: dnp3_frozen_counter_16woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 163 163

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 10
   frozen counter 16 bit without flag

.. zeek:id:: dnp3_frozen_counter_32wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 138 138

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 1
   frozen counter 32 bit with flag

.. zeek:id:: dnp3_frozen_counter_32wFlagTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 148 148

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 5
   frozen counter 32 bit with flag and time

.. zeek:id:: dnp3_frozen_counter_32woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 158 158

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 9
   frozen counter 32 bit without flag

.. zeek:id:: dnp3_header_block
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 82 82

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, len: :zeek:type:`count`, ctrl: :zeek:type:`count`, dest_addr: :zeek:type:`count`, src_addr: :zeek:type:`count`)

   Generated for an additional header that the DNP3 analyzer passes to the
   script-level. This header mimics the DNP3 transport-layer yet is only passed
   once for each sequence of DNP3 records (which are otherwise reassembled and
   treated as a single entity).
   

   :param c: The connection the DNP3 communication is part of.
   

   :param is_orig: True if this reflects originator-side activity.
   

   :param len:   the "length" field in the DNP3 Pseudo Link Layer.
   

   :param ctrl:  the "control" field in the DNP3 Pseudo Link Layer.
   

   :param dest_addr: the "destination" field in the DNP3 Pseudo Link Layer.
   

   :param src_addr: the "source" field in the DNP3 Pseudo Link Layer.
   

.. zeek:id:: dnp3_object_header
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 50 50

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, obj_type: :zeek:type:`count`, qua_field: :zeek:type:`count`, number: :zeek:type:`count`, rf_low: :zeek:type:`count`, rf_high: :zeek:type:`count`)

   Generated for the object header found in both DNP3 requests and responses.
   

   :param c: The connection the DNP3 communication is part of.
   

   :param is_orig: True if this reflects originator-side activity.
   

   :param obj_type: type of object, which is classified based on an 8-bit group number
             and an 8-bit variation number.
   

   :param qua_field: qualifier field.
   

   :param number: TODO.
   

   :param rf_low: the structure of the range field depends on the qualified field.
           In some cases, the range field contains only one logic part, e.g.,
           number of objects, so only *rf_low* contains useful values.
   

   :param rf_high: in some cases, the range field contains two logic parts, e.g., start
            index and stop index, so *rf_low* contains the start index
            while *rf_high* contains the stop index.
   

.. zeek:id:: dnp3_object_prefix
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 62 62

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix_value: :zeek:type:`count`)

   Generated for the prefix before a DNP3 object. The structure and the meaning
   of the prefix are defined by the qualifier field.
   

   :param c: The connection the DNP3 communication is part of.
   

   :param is_orig: True if this reflects originator-side activity.
   

   :param prefix_value: The prefix.
   

.. zeek:id:: dnp3_pcb
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 113 113

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, control_code: :zeek:type:`count`, count8: :zeek:type:`count`, on_time: :zeek:type:`count`, off_time: :zeek:type:`count`, status_code: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 12 and variation number 2

   :param PCB: Pattern Control Block

.. zeek:id:: dnp3_response_data_object
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 99 99

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, data_value: :zeek:type:`count`)

   Generated for a DNP3 "Response_Data_Object".
   The "Response_Data_Object" contains two parts: object prefix and object
   data. In most cases, object data are defined by new record types. But
   in a few cases, object data are directly basic types, such as int16_t, or
   int8_t; thus we use an additional *data_value* to record the values of those
   object data.
   

   :param c: The connection the DNP3 communication is part of.
   

   :param is_orig: True if this reflects originator-side activity.
   

   :param data_value: The value for those objects that carry their information here
               directly.
   


