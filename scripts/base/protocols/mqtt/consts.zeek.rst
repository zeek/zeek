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

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "connack",
            [9] = "suback",
            [6] = "pubrel",
            [11] = "unsuback",
            [14] = "disconnect",
            [4] = "puback",
            [1] = "connect",
            [8] = "subscribe",
            [7] = "pubcomp",
            [5] = "pubrec",
            [10] = "unsubscribe",
            [3] = "publish",
            [12] = "pingreq",
            [13] = "pingresp"
         }



.. zeek:id:: MQTT::qos_levels

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "exactly once",
            [1] = "at least once",
            [0] = "at most once"
         }



.. zeek:id:: MQTT::return_codes

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "Refused: identifier rejected",
            [4] = "Refused: bad user name or password",
            [1] = "Refused: unacceptable protocol version",
            [5] = "Refused: not authorized",
            [0] = "Connection Accepted",
            [3] = "Refused: server unavailable"
         }



.. zeek:id:: MQTT::versions

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [4] = "3.1.1",
            [5] = "5.0",
            [3] = "3.1"
         }




