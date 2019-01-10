:tocdepth: 3

base/bif/plugins/Bro_DNP3.events.bif.bro
========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
==================================================================== ===========================================================================
:bro:id:`dnp3_analog_input_16wFlag`: :bro:type:`event`               Generated for DNP3 objects with the group number 30 and variation number 2
                                                                     analog input 16 bit with flag
:bro:id:`dnp3_analog_input_16woFlag`: :bro:type:`event`              Generated for DNP3 objects with the group number 30 and variation number 4
                                                                     analog input 16 bit without flag
:bro:id:`dnp3_analog_input_32wFlag`: :bro:type:`event`               Generated for DNP3 objects with the group number 30 and variation number 1
                                                                     analog input 32 bit with flag
:bro:id:`dnp3_analog_input_32woFlag`: :bro:type:`event`              Generated for DNP3 objects with the group number 30 and variation number 3
                                                                     analog input 32 bit without flag
:bro:id:`dnp3_analog_input_DPwFlag`: :bro:type:`event`               Generated for DNP3 objects with the group number 30 and variation number 6
                                                                     analog input double precision, float point with flag
:bro:id:`dnp3_analog_input_SPwFlag`: :bro:type:`event`               Generated for DNP3 objects with the group number 30 and variation number 5
                                                                     analog input single precision, float point with flag
:bro:id:`dnp3_analog_input_event_16wTime`: :bro:type:`event`         Generated for DNP3 objects with the group number 32 and variation number 4
                                                                     analog input event 16 bit with time
:bro:id:`dnp3_analog_input_event_16woTime`: :bro:type:`event`        Generated for DNP3 objects with the group number 32 and variation number 2
                                                                     analog input event 16 bit without time
:bro:id:`dnp3_analog_input_event_32wTime`: :bro:type:`event`         Generated for DNP3 objects with the group number 32 and variation number 3
                                                                     analog input event 32 bit with time
:bro:id:`dnp3_analog_input_event_32woTime`: :bro:type:`event`        Generated for DNP3 objects with the group number 32 and variation number 1
                                                                     analog input event 32 bit without time
:bro:id:`dnp3_analog_input_event_DPwTime`: :bro:type:`event`         Generated for DNP3 objects with the group number 32 and variation number 8
                                                                     analog input event double-precisiion float point with time
:bro:id:`dnp3_analog_input_event_DPwoTime`: :bro:type:`event`        Generated for DNP3 objects with the group number 32 and variation number 6
                                                                     analog input event double-precision float point without time
:bro:id:`dnp3_analog_input_event_SPwTime`: :bro:type:`event`         Generated for DNP3 objects with the group number 32 and variation number 7
                                                                     analog input event single-precision float point with time
:bro:id:`dnp3_analog_input_event_SPwoTime`: :bro:type:`event`        Generated for DNP3 objects with the group number 32 and variation number 5
                                                                     analog input event single-precision float point without time
:bro:id:`dnp3_application_request_header`: :bro:type:`event`         Generated for a DNP3 request header.
:bro:id:`dnp3_application_response_header`: :bro:type:`event`        Generated for a DNP3 response header.
:bro:id:`dnp3_attribute_common`: :bro:type:`event`                   Generated for DNP3 attributes.
:bro:id:`dnp3_counter_16wFlag`: :bro:type:`event`                    Generated for DNP3 objects with the group number 20 and variation number 2
                                                                     counter 16 bit with flag
:bro:id:`dnp3_counter_16woFlag`: :bro:type:`event`                   Generated for DNP3 objects with the group number 20 and variation number 6
                                                                     counter 16 bit without flag
:bro:id:`dnp3_counter_32wFlag`: :bro:type:`event`                    Generated for DNP3 objects with the group number 20 and variation number 1
                                                                     counter 32 bit with flag
:bro:id:`dnp3_counter_32woFlag`: :bro:type:`event`                   Generated for DNP3 objects with the group number 20 and variation number 5
                                                                     counter 32 bit without flag
:bro:id:`dnp3_crob`: :bro:type:`event`                               Generated for DNP3 objects with the group number 12 and variation number 1
                                                                     CROB: control relay output block
:bro:id:`dnp3_debug_byte`: :bro:type:`event`                         Debugging event generated by the DNP3 analyzer.
:bro:id:`dnp3_file_transport`: :bro:type:`event`                     g70
:bro:id:`dnp3_frozen_analog_input_16wFlag`: :bro:type:`event`        Generated for DNP3 objects with the group number 31 and variation number 2
                                                                     frozen analog input 16 bit with flag
:bro:id:`dnp3_frozen_analog_input_16wTime`: :bro:type:`event`        Generated for DNP3 objects with the group number 31 and variation number 4
                                                                     frozen analog input 16 bit with time-of-freeze
:bro:id:`dnp3_frozen_analog_input_16woFlag`: :bro:type:`event`       Generated for DNP3 objects with the group number 31 and variation number 6
                                                                     frozen analog input 16 bit without flag
:bro:id:`dnp3_frozen_analog_input_32wFlag`: :bro:type:`event`        Generated for DNP3 objects with the group number 31 and variation number 1
                                                                     frozen analog input 32 bit with flag
:bro:id:`dnp3_frozen_analog_input_32wTime`: :bro:type:`event`        Generated for DNP3 objects with the group number 31 and variation number 3
                                                                     frozen analog input 32 bit with time-of-freeze
:bro:id:`dnp3_frozen_analog_input_32woFlag`: :bro:type:`event`       Generated for DNP3 objects with the group number 31 and variation number 5
                                                                     frozen analog input 32 bit without flag
:bro:id:`dnp3_frozen_analog_input_DPwFlag`: :bro:type:`event`        Generated for DNP3 objects with the group number 31 and variation number 8
                                                                     frozen analog input double-precision, float point with flag
:bro:id:`dnp3_frozen_analog_input_SPwFlag`: :bro:type:`event`        Generated for DNP3 objects with the group number 31 and variation number 7
                                                                     frozen analog input single-precision, float point with flag
:bro:id:`dnp3_frozen_analog_input_event_16wTime`: :bro:type:`event`  Generated for DNP3 objects with the group number 33 and variation number 4
                                                                     frozen analog input event 16 bit with time
:bro:id:`dnp3_frozen_analog_input_event_16woTime`: :bro:type:`event` Generated for DNP3 objects with the group number 33 and variation number 2
                                                                     frozen analog input event 16 bit without time
:bro:id:`dnp3_frozen_analog_input_event_32wTime`: :bro:type:`event`  Generated for DNP3 objects with the group number 33 and variation number 3
                                                                     frozen analog input event 32 bit with time
:bro:id:`dnp3_frozen_analog_input_event_32woTime`: :bro:type:`event` Generated for DNP3 objects with the group number 33 and variation number 1
                                                                     frozen analog input event 32 bit without time
:bro:id:`dnp3_frozen_analog_input_event_DPwTime`: :bro:type:`event`  Generated for DNP3 objects with the group number 34 and variation number 8
                                                                     frozen analog input event double-precision float point with time
:bro:id:`dnp3_frozen_analog_input_event_DPwoTime`: :bro:type:`event` Generated for DNP3 objects with the group number 33 and variation number 6
                                                                     frozen analog input event double-precision float point without time
:bro:id:`dnp3_frozen_analog_input_event_SPwTime`: :bro:type:`event`  Generated for DNP3 objects with the group number 33 and variation number 7
                                                                     frozen analog input event single-precision float point with time
:bro:id:`dnp3_frozen_analog_input_event_SPwoTime`: :bro:type:`event` Generated for DNP3 objects with the group number 33 and variation number 5
                                                                     frozen analog input event single-precision float point without time
:bro:id:`dnp3_frozen_counter_16wFlag`: :bro:type:`event`             Generated for DNP3 objects with the group number 21 and variation number 2
                                                                     frozen counter 16 bit with flag
:bro:id:`dnp3_frozen_counter_16wFlagTime`: :bro:type:`event`         Generated for DNP3 objects with the group number 21 and variation number 6
                                                                     frozen counter 16 bit with flag and time
:bro:id:`dnp3_frozen_counter_16woFlag`: :bro:type:`event`            Generated for DNP3 objects with the group number 21 and variation number 10
                                                                     frozen counter 16 bit without flag
:bro:id:`dnp3_frozen_counter_32wFlag`: :bro:type:`event`             Generated for DNP3 objects with the group number 21 and variation number 1
                                                                     frozen counter 32 bit with flag
:bro:id:`dnp3_frozen_counter_32wFlagTime`: :bro:type:`event`         Generated for DNP3 objects with the group number 21 and variation number 5
                                                                     frozen counter 32 bit with flag and time
:bro:id:`dnp3_frozen_counter_32woFlag`: :bro:type:`event`            Generated for DNP3 objects with the group number 21 and variation number 9
                                                                     frozen counter 32 bit without flag
:bro:id:`dnp3_header_block`: :bro:type:`event`                       Generated for an additional header that the DNP3 analyzer passes to the
                                                                     script-level.
:bro:id:`dnp3_object_header`: :bro:type:`event`                      Generated for the object header found in both DNP3 requests and responses.
:bro:id:`dnp3_object_prefix`: :bro:type:`event`                      Generated for the prefix before a DNP3 object.
:bro:id:`dnp3_pcb`: :bro:type:`event`                                Generated for DNP3 objects with the group number 12 and variation number 2
                                                                     PCB: Pattern Control Block
:bro:id:`dnp3_response_data_object`: :bro:type:`event`               Generated for a DNP3 "Response_Data_Object".
==================================================================== ===========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: dnp3_analog_input_16wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 2
   analog input 16 bit with flag

.. bro:id:: dnp3_analog_input_16woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 4
   analog input 16 bit without flag

.. bro:id:: dnp3_analog_input_32wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 1
   analog input 32 bit with flag

.. bro:id:: dnp3_analog_input_32woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 3
   analog input 32 bit without flag

.. bro:id:: dnp3_analog_input_DPwFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value_low: :bro:type:`count`, value_high: :bro:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 6
   analog input double precision, float point with flag

.. bro:id:: dnp3_analog_input_SPwFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 5
   analog input single precision, float point with flag

.. bro:id:: dnp3_analog_input_event_16wTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 4
   analog input event 16 bit with time

.. bro:id:: dnp3_analog_input_event_16woTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 2
   analog input event 16 bit without time

.. bro:id:: dnp3_analog_input_event_32wTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 3
   analog input event 32 bit with time

.. bro:id:: dnp3_analog_input_event_32woTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 1
   analog input event 32 bit without time

.. bro:id:: dnp3_analog_input_event_DPwTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value_low: :bro:type:`count`, value_high: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 8
   analog input event double-precisiion float point with time

.. bro:id:: dnp3_analog_input_event_DPwoTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value_low: :bro:type:`count`, value_high: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 6
   analog input event double-precision float point without time

.. bro:id:: dnp3_analog_input_event_SPwTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 7
   analog input event single-precision float point with time

.. bro:id:: dnp3_analog_input_event_SPwoTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 5
   analog input event single-precision float point without time

.. bro:id:: dnp3_application_request_header

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, application: :bro:type:`count`, fc: :bro:type:`count`)

   Generated for a DNP3 request header.
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :fc: function code.
   

.. bro:id:: dnp3_application_response_header

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, application: :bro:type:`count`, fc: :bro:type:`count`, iin: :bro:type:`count`)

   Generated for a DNP3 response header.
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :fc: function code.
   

   :iin: internal indication number.
   

.. bro:id:: dnp3_attribute_common

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, data_type_code: :bro:type:`count`, leng: :bro:type:`count`, attribute_obj: :bro:type:`string`)

   Generated for DNP3 attributes.

.. bro:id:: dnp3_counter_16wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 2
   counter 16 bit with flag

.. bro:id:: dnp3_counter_16woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 6
   counter 16 bit without flag

.. bro:id:: dnp3_counter_32wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 1
   counter 32 bit with flag

.. bro:id:: dnp3_counter_32woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 5
   counter 32 bit without flag

.. bro:id:: dnp3_crob

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, control_code: :bro:type:`count`, count8: :bro:type:`count`, on_time: :bro:type:`count`, off_time: :bro:type:`count`, status_code: :bro:type:`count`)

   Generated for DNP3 objects with the group number 12 and variation number 1

   :CROB: control relay output block

.. bro:id:: dnp3_debug_byte

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, debug: :bro:type:`string`)

   Debugging event generated by the DNP3 analyzer. The "Debug_Byte" binpac unit
   generates this for unknown "cases". The user can use it to debug the byte
   string to check what caused the malformed network packets.

.. bro:id:: dnp3_file_transport

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, file_handle: :bro:type:`count`, block_num: :bro:type:`count`, file_data: :bro:type:`string`)

   g70

.. bro:id:: dnp3_frozen_analog_input_16wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 2
   frozen analog input 16 bit with flag

.. bro:id:: dnp3_frozen_analog_input_16wTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 4
   frozen analog input 16 bit with time-of-freeze

.. bro:id:: dnp3_frozen_analog_input_16woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 6
   frozen analog input 16 bit without flag

.. bro:id:: dnp3_frozen_analog_input_32wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 1
   frozen analog input 32 bit with flag

.. bro:id:: dnp3_frozen_analog_input_32wTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 3
   frozen analog input 32 bit with time-of-freeze

.. bro:id:: dnp3_frozen_analog_input_32woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 5
   frozen analog input 32 bit without flag

.. bro:id:: dnp3_frozen_analog_input_DPwFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value_low: :bro:type:`count`, frozen_value_high: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 8
   frozen analog input double-precision, float point with flag

.. bro:id:: dnp3_frozen_analog_input_SPwFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 7
   frozen analog input single-precision, float point with flag

.. bro:id:: dnp3_frozen_analog_input_event_16wTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 4
   frozen analog input event 16 bit with time

.. bro:id:: dnp3_frozen_analog_input_event_16woTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 2
   frozen analog input event 16 bit without time

.. bro:id:: dnp3_frozen_analog_input_event_32wTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 3
   frozen analog input event 32 bit with time

.. bro:id:: dnp3_frozen_analog_input_event_32woTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 1
   frozen analog input event 32 bit without time

.. bro:id:: dnp3_frozen_analog_input_event_DPwTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value_low: :bro:type:`count`, frozen_value_high: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 34 and variation number 8
   frozen analog input event double-precision float point with time

.. bro:id:: dnp3_frozen_analog_input_event_DPwoTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value_low: :bro:type:`count`, frozen_value_high: :bro:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 6
   frozen analog input event double-precision float point without time

.. bro:id:: dnp3_frozen_analog_input_event_SPwTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 7
   frozen analog input event single-precision float point with time

.. bro:id:: dnp3_frozen_analog_input_event_SPwoTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 5
   frozen analog input event single-precision float point without time

.. bro:id:: dnp3_frozen_counter_16wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 2
   frozen counter 16 bit with flag

.. bro:id:: dnp3_frozen_counter_16wFlagTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, count_value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 6
   frozen counter 16 bit with flag and time

.. bro:id:: dnp3_frozen_counter_16woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 10
   frozen counter 16 bit without flag

.. bro:id:: dnp3_frozen_counter_32wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 1
   frozen counter 32 bit with flag

.. bro:id:: dnp3_frozen_counter_32wFlagTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, count_value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 5
   frozen counter 32 bit with flag and time

.. bro:id:: dnp3_frozen_counter_32woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 9
   frozen counter 32 bit without flag

.. bro:id:: dnp3_header_block

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, len: :bro:type:`count`, ctrl: :bro:type:`count`, dest_addr: :bro:type:`count`, src_addr: :bro:type:`count`)

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
   

.. bro:id:: dnp3_object_header

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, obj_type: :bro:type:`count`, qua_field: :bro:type:`count`, number: :bro:type:`count`, rf_low: :bro:type:`count`, rf_high: :bro:type:`count`)

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
   

.. bro:id:: dnp3_object_prefix

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix_value: :bro:type:`count`)

   Generated for the prefix before a DNP3 object. The structure and the meaning
   of the prefix are defined by the qualifier field.
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :prefix_value: The prefix.
   

.. bro:id:: dnp3_pcb

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, control_code: :bro:type:`count`, count8: :bro:type:`count`, on_time: :bro:type:`count`, off_time: :bro:type:`count`, status_code: :bro:type:`count`)

   Generated for DNP3 objects with the group number 12 and variation number 2

   :PCB: Pattern Control Block

.. bro:id:: dnp3_response_data_object

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, data_value: :bro:type:`count`)

   Generated for a DNP3 "Response_Data_Object".
   The "Response_Data_Object" contains two parts: object prefix and object
   data. In most cases, object data are defined by new record types. But
   in a few cases, object data are directly basic types, such as int16, or
   int8; thus we use an additional *data_value* to record the values of those
   object data.
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :data_value: The value for those objects that carry their information here
               directly.
   


