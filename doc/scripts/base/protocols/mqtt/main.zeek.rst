:tocdepth: 3

base/protocols/mqtt/main.zeek
=============================
.. zeek:namespace:: MQTT

Implements base functionality for MQTT (v3.1.1) analysis.
Generates the mqtt.log file.

:Namespace: MQTT
:Imports: :doc:`base/protocols/mqtt/consts.zeek </scripts/base/protocols/mqtt/consts.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
============================================================ ==========================
:zeek:id:`MQTT::ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for MQTT.
============================================================ ==========================

Types
#####
================================================================== ======================================================================
:zeek:type:`MQTT::ConnectInfo`: :zeek:type:`record`                
:zeek:type:`MQTT::PublishInfo`: :zeek:type:`record`                
:zeek:type:`MQTT::State`: :zeek:type:`record`                      Data structure to track pub/sub messaging state of a given connection.
:zeek:type:`MQTT::SubUnsub`: :zeek:type:`enum` :zeek:attr:`&redef` 
:zeek:type:`MQTT::SubscribeInfo`: :zeek:type:`record`              
================================================================== ======================================================================

Redefinitions
#############
============================================ =============================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      
                                             
                                             * :zeek:enum:`MQTT::CONNECT_LOG`
                                             
                                             * :zeek:enum:`MQTT::PUBLISH_LOG`
                                             
                                             * :zeek:enum:`MQTT::SUBSCRIBE_LOG`
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               mqtt: :zeek:type:`MQTT::ConnectInfo` :zeek:attr:`&optional`
                                             
                                               mqtt_state: :zeek:type:`MQTT::State` :zeek:attr:`&optional`
============================================ =============================================================

Events
######
============================================= ====================================================================
:zeek:id:`MQTT::log_mqtt`: :zeek:type:`event` Event that can be handled to access the MQTT record as it is sent on
                                              to the logging framework.
============================================= ====================================================================

Hooks
#####
=================================================================== =
:zeek:id:`MQTT::log_policy_connect`: :zeek:type:`Log::PolicyHook`   
:zeek:id:`MQTT::log_policy_publish`: :zeek:type:`Log::PolicyHook`   
:zeek:id:`MQTT::log_policy_subscribe`: :zeek:type:`Log::PolicyHook` 
=================================================================== =

Functions
#########
======================================================== ==========================================================================
:zeek:id:`MQTT::publish_expire`: :zeek:type:`function`   The expiration function for published messages that haven't been logged
                                                         yet simply causes the message to be logged.
:zeek:id:`MQTT::subscribe_expire`: :zeek:type:`function` The expiration function for subscription messages that haven't been logged
                                                         yet simply causes the message to be logged.
======================================================== ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: MQTT::ports
   :source-code: base/protocols/mqtt/main.zeek 16 16

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            1883/tcp
         }


   Well-known ports for MQTT.

Types
#####
.. zeek:type:: MQTT::ConnectInfo
   :source-code: base/protocols/mqtt/main.zeek 27 48

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when the event happened


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports


   .. zeek:field:: proto_name :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Indicates the protocol name


   .. zeek:field:: proto_version :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The version of the protocol in use


   .. zeek:field:: client_id :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Unique identifier for the client


   .. zeek:field:: connect_status :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Status message from the server in response to the connect request


   .. zeek:field:: will_topic :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Topic to publish a "last will and testament" message to


   .. zeek:field:: will_payload :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Payload to publish as a "last will and testament"



.. zeek:type:: MQTT::PublishInfo
   :source-code: base/protocols/mqtt/main.zeek 70 110

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when the publish message started


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      UID for the connection


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      ID fields for the connection


   .. zeek:field:: from_client :zeek:type:`bool` :zeek:attr:`&log`

      Indicates if the message was published by the client of
      this connection or published to the client.


   .. zeek:field:: retain :zeek:type:`bool` :zeek:attr:`&log`

      Indicates if the message was to be retained by the server


   .. zeek:field:: qos :zeek:type:`string` :zeek:attr:`&log`

      QoS level set for the message


   .. zeek:field:: status :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&default` = ``"incomplete_qos"`` :zeek:attr:`&optional`

      Status of the published message. This will be set to "incomplete_qos"
      if the full back and forth for the requested level of QoS was not seen.
      Otherwise if it's successful the field will be "ok".


   .. zeek:field:: topic :zeek:type:`string` :zeek:attr:`&log`

      Topic the message was published to


   .. zeek:field:: payload :zeek:type:`string` :zeek:attr:`&log`

      Payload of the message


   .. zeek:field:: payload_len :zeek:type:`count` :zeek:attr:`&log`

      The actual length of the payload in the case the *payload*
      field's contents were truncated according to
      :zeek:see:`MQTT::max_payload_size`.


   .. zeek:field:: ack :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Track if the message was acked


   .. zeek:field:: rec :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Indicates if the server sent the RECEIVED qos message


   .. zeek:field:: rel :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Indicates if the client sent the RELEASE qos message


   .. zeek:field:: comp :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Indicates if the server sent the COMPLETE qos message


   .. zeek:field:: qos_level :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      Internally used for comparing numeric qos level



.. zeek:type:: MQTT::State
   :source-code: base/protocols/mqtt/main.zeek 125 131

   :Type: :zeek:type:`record`


   .. zeek:field:: publish :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`MQTT::PublishInfo` :zeek:attr:`&optional` :zeek:attr:`&write_expire` = ``5.0 secs`` :zeek:attr:`&expire_func` = :zeek:see:`MQTT::publish_expire`

      Published messages that haven't been logged yet.


   .. zeek:field:: subscribe :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`MQTT::SubscribeInfo` :zeek:attr:`&optional` :zeek:attr:`&write_expire` = ``5.0 secs`` :zeek:attr:`&expire_func` = :zeek:see:`MQTT::subscribe_expire`

      Subscription/unsubscription messages that haven't been ACK'd or
      logged yet.


   Data structure to track pub/sub messaging state of a given connection.

.. zeek:type:: MQTT::SubUnsub
   :source-code: base/protocols/mqtt/main.zeek 22 26

   :Type: :zeek:type:`enum`

      .. zeek:enum:: MQTT::SUBSCRIBE MQTT::SubUnsub

      .. zeek:enum:: MQTT::UNSUBSCRIBE MQTT::SubUnsub
   :Attributes: :zeek:attr:`&redef`


.. zeek:type:: MQTT::SubscribeInfo
   :source-code: base/protocols/mqtt/main.zeek 50 68

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when the subscribe or unsubscribe request started


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      UID for the connection


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      ID fields for the connection


   .. zeek:field:: action :zeek:type:`MQTT::SubUnsub` :zeek:attr:`&log`

      Indicates if a subscribe or unsubscribe action is taking place


   .. zeek:field:: topics :zeek:type:`string_vec` :zeek:attr:`&log`

      The topics (or topic patterns) being subscribed to


   .. zeek:field:: qos_levels :zeek:type:`index_vec` :zeek:attr:`&log` :zeek:attr:`&optional`

      QoS levels requested for messages from subscribed topics


   .. zeek:field:: granted_qos_level :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      QoS level the server granted


   .. zeek:field:: ack :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Indicates if the request was acked by the server



Events
######
.. zeek:id:: MQTT::log_mqtt
   :source-code: base/protocols/mqtt/main.zeek 114 114

   :Type: :zeek:type:`event` (rec: :zeek:type:`MQTT::ConnectInfo`)

   Event that can be handled to access the MQTT record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: MQTT::log_policy_connect
   :source-code: base/protocols/mqtt/main.zeek 18 18

   :Type: :zeek:type:`Log::PolicyHook`


.. zeek:id:: MQTT::log_policy_publish
   :source-code: base/protocols/mqtt/main.zeek 20 20

   :Type: :zeek:type:`Log::PolicyHook`


.. zeek:id:: MQTT::log_policy_subscribe
   :source-code: base/protocols/mqtt/main.zeek 19 19

   :Type: :zeek:type:`Log::PolicyHook`


Functions
#########
.. zeek:id:: MQTT::publish_expire
   :source-code: base/protocols/mqtt/main.zeek 134 138

   :Type: :zeek:type:`function` (tbl: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`MQTT::PublishInfo`, idx: :zeek:type:`count`) : :zeek:type:`interval`

   The expiration function for published messages that haven't been logged
   yet simply causes the message to be logged.

.. zeek:id:: MQTT::subscribe_expire
   :source-code: base/protocols/mqtt/main.zeek 140 144

   :Type: :zeek:type:`function` (tbl: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`MQTT::SubscribeInfo`, idx: :zeek:type:`count`) : :zeek:type:`interval`

   The expiration function for subscription messages that haven't been logged
   yet simply causes the message to be logged.


