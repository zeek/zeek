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
                                                                       analog input event double-precisiion float point with time
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

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 2
   analog input 16 bit with flag

.. zeek:id:: dnp3_analog_input_16woFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 4
   analog input 16 bit without flag

.. zeek:id:: dnp3_analog_input_32wFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 1
   analog input 32 bit with flag

.. zeek:id:: dnp3_analog_input_32woFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 3
   analog input 32 bit without flag

.. zeek:id:: dnp3_analog_input_DPwFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value_low: :zeek:type:`count`, value_high: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 6
   analog input double precision, float point with flag

.. zeek:id:: dnp3_analog_input_SPwFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 5
   analog input single precision, float point with flag

.. zeek:id:: dnp3_analog_input_event_16wTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 4
   analog input event 16 bit with time

.. zeek:id:: dnp3_analog_input_event_16woTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 2
   analog input event 16 bit without time

.. zeek:id:: dnp3_analog_input_event_32wTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 3
   analog input event 32 bit with time

.. zeek:id:: dnp3_analog_input_event_32woTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 1
   analog input event 32 bit without time

.. zeek:id:: dnp3_analog_input_event_DPwTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value_low: :zeek:type:`count`, value_high: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 8
   analog input event double-precisiion float point with time

.. zeek:id:: dnp3_analog_input_event_DPwoTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value_low: :zeek:type:`count`, value_high: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 6
   analog input event double-precision float point without time

.. zeek:id:: dnp3_analog_input_event_SPwTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 7
   analog input event single-precision float point with time

.. zeek:id:: dnp3_analog_input_event_SPwoTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 5
   analog input event single-precision float point without time

.. zeek:id:: dnp3_application_request_header

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, application: :zeek:type:`count`, fc: :zeek:type:`count`)

   Generated for a DNP3 request header.
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :fc: function code.
   

.. zeek:id:: dnp3_application_response_header

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, application: :zeek:type:`count`, fc: :zeek:type:`count`, iin: :zeek:type:`count`)

   Generated for a DNP3 response header.
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :fc: function code.
   

   :iin: internal indication number.
   

.. zeek:id:: dnp3_attribute_common

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, data_type_code: :zeek:type:`count`, leng: :zeek:type:`count`, attribute_obj: :zeek:type:`string`)

   Generated for DNP3 attributes.

.. zeek:id:: dnp3_counter_16wFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 2
   counter 16 bit with flag

.. zeek:id:: dnp3_counter_16woFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 6
   counter 16 bit without flag

.. zeek:id:: dnp3_counter_32wFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 1
   counter 32 bit with flag

.. zeek:id:: dnp3_counter_32woFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 5
   counter 32 bit without flag

.. zeek:id:: dnp3_crob

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, control_code: :zeek:type:`count`, count8: :zeek:type:`count`, on_time: :zeek:type:`count`, off_time: :zeek:type:`count`, status_code: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 12 and variation number 1

   :CROB: control relay output block

.. zeek:id:: dnp3_debug_byte

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, debug: :zeek:type:`string`)

   Debugging event generated by the DNP3 analyzer. The "Debug_Byte" binpac unit
   generates this for unknown "cases". The user can use it to debug the byte
   string to check what caused the malformed network packets.

.. zeek:id:: dnp3_file_transport

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, file_handle: :zeek:type:`count`, block_num: :zeek:type:`count`, file_data: :zeek:type:`string`)

   g70

.. zeek:id:: dnp3_frozen_analog_input_16wFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 2
   frozen analog input 16 bit with flag

.. zeek:id:: dnp3_frozen_analog_input_16wTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 4
   frozen analog input 16 bit with time-of-freeze

.. zeek:id:: dnp3_frozen_analog_input_16woFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 6
   frozen analog input 16 bit without flag

.. zeek:id:: dnp3_frozen_analog_input_32wFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 1
   frozen analog input 32 bit with flag

.. zeek:id:: dnp3_frozen_analog_input_32wTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 3
   frozen analog input 32 bit with time-of-freeze

.. zeek:id:: dnp3_frozen_analog_input_32woFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 5
   frozen analog input 32 bit without flag

.. zeek:id:: dnp3_frozen_analog_input_DPwFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value_low: :zeek:type:`count`, frozen_value_high: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 8
   frozen analog input double-precision, float point with flag

.. zeek:id:: dnp3_frozen_analog_input_SPwFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 7
   frozen analog input single-precision, float point with flag

.. zeek:id:: dnp3_frozen_analog_input_event_16wTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 4
   frozen analog input event 16 bit with time

.. zeek:id:: dnp3_frozen_analog_input_event_16woTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 2
   frozen analog input event 16 bit without time

.. zeek:id:: dnp3_frozen_analog_input_event_32wTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 3
   frozen analog input event 32 bit with time

.. zeek:id:: dnp3_frozen_analog_input_event_32woTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 1
   frozen analog input event 32 bit without time

.. zeek:id:: dnp3_frozen_analog_input_event_DPwTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value_low: :zeek:type:`count`, frozen_value_high: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 34 and variation number 8
   frozen analog input event double-precision float point with time

.. zeek:id:: dnp3_frozen_analog_input_event_DPwoTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value_low: :zeek:type:`count`, frozen_value_high: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 6
   frozen analog input event double-precision float point without time

.. zeek:id:: dnp3_frozen_analog_input_event_SPwTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 7
   frozen analog input event single-precision float point with time

.. zeek:id:: dnp3_frozen_analog_input_event_SPwoTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 5
   frozen analog input event single-precision float point without time

.. zeek:id:: dnp3_frozen_counter_16wFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 2
   frozen counter 16 bit with flag

.. zeek:id:: dnp3_frozen_counter_16wFlagTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 6
   frozen counter 16 bit with flag and time

.. zeek:id:: dnp3_frozen_counter_16woFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 10
   frozen counter 16 bit without flag

.. zeek:id:: dnp3_frozen_counter_32wFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 1
   frozen counter 32 bit with flag

.. zeek:id:: dnp3_frozen_counter_32wFlagTime

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 5
   frozen counter 32 bit with flag and time

.. zeek:id:: dnp3_frozen_counter_32woFlag

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 9
   frozen counter 32 bit without flag

.. zeek:id:: dnp3_header_block

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, len: :zeek:type:`count`, ctrl: :zeek:type:`count`, dest_addr: :zeek:type:`count`, src_addr: :zeek:type:`count`)

   Generated for an additional header that the DNP3 analyzer passes to the
   script-level. This header mimics the DNP3 transport-layer yet is only passed
   once for each sequence of DNP3 records (which are otherwise reassembled and
   treated as a single entity).
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :len:   the "length" field in the DNP3 Pseudo Link Layer.
   

   :ctrl:  the "control" field in the DNP3 Pseudo Link Layer.
   

   :dest_addr: the "destination" field in the DNP3 Pseudo Link Layer.
   

   :src_addr: the "source" field in the DNP3 Pseudo Link Layer.
   

.. zeek:id:: dnp3_object_header

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, obj_type: :zeek:type:`count`, qua_field: :zeek:type:`count`, number: :zeek:type:`count`, rf_low: :zeek:type:`count`, rf_high: :zeek:type:`count`)

   Generated for the object header found in both DNP3 requests and responses.
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :obj_type: type of object, which is classified based on an 8-bit group number
             and an 8-bit variation number.
   

   :qua_field: qualifier field.
   

   :number: TODO.
   

   :rf_low: the structure of the range field depends on the qualified field.
           In some cases, the range field contains only one logic part, e.g.,
           number of objects, so only *rf_low* contains useful values.
   

   :rf_high: in some cases, the range field contains two logic parts, e.g., start
            index and stop index, so *rf_low* contains the start index
            while *rf_high* contains the stop index.
   

.. zeek:id:: dnp3_object_prefix

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix_value: :zeek:type:`count`)

   Generated for the prefix before a DNP3 object. The structure and the meaning
   of the prefix are defined by the qualifier field.
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :prefix_value: The prefix.
   

.. zeek:id:: dnp3_pcb

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, control_code: :zeek:type:`count`, count8: :zeek:type:`count`, on_time: :zeek:type:`count`, off_time: :zeek:type:`count`, status_code: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 12 and variation number 2

   :PCB: Pattern Control Block

.. zeek:id:: dnp3_response_data_object

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, data_value: :zeek:type:`count`)

   Generated for a DNP3 "Response_Data_Object".
   The "Response_Data_Object" contains two parts: object prefix and object
   data. In most cases, object data are defined by new record types. But
   in a few cases, object data are directly basic types, such as int16_t, or
   int8_t; thus we use an additional *data_value* to record the values of those
   object data.
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :data_value: The value for those objects that carry their information here
               directly.
   


