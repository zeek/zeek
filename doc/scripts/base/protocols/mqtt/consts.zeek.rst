:tocdepth: 3

base/protocols/mqtt/consts.zeek
===============================
.. zeek:namespace:: MQTT

Constants definitions for MQTT.

:Namespace: MQTT

Summary
~~~~~~~
Constants
#########
=============================================================================================== =
:zeek:id:`MQTT::msg_types`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`    
:zeek:id:`MQTT::qos_levels`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`   
:zeek:id:`MQTT::return_codes`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` 
:zeek:id:`MQTT::versions`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`     
=============================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: MQTT::msg_types
   :source-code: base/protocols/mqtt/consts.zeek 6 6

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "connack",
            [11] = "unsuback",
            [5] = "pubrec",
            [7] = "pubcomp",
            [6] = "pubrel",
            [10] = "unsubscribe",
            [14] = "disconnect",
            [4] = "puback",
            [13] = "pingresp",
            [12] = "pingreq",
            [8] = "subscribe",
            [3] = "publish",
            [9] = "suback",
            [1] = "connect"
         }



.. zeek:id:: MQTT::qos_levels
   :source-code: base/protocols/mqtt/consts.zeek 29 29

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [0] = "at most once",
            [2] = "exactly once",
            [1] = "at least once"
         }



.. zeek:id:: MQTT::return_codes
   :source-code: base/protocols/mqtt/consts.zeek 35 35

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "Refused: identifier rejected",
            [3] = "Refused: server unavailable",
            [5] = "Refused: not authorized",
            [0] = "Connection Accepted",
            [4] = "Refused: bad user name or password",
            [1] = "Refused: unacceptable protocol version"
         }



.. zeek:id:: MQTT::versions
   :source-code: base/protocols/mqtt/consts.zeek 23 23

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [4] = "3.1.1",
            [3] = "3.1",
            [5] = "5.0"
         }




