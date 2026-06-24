:tocdepth: 3

base/protocols/ntp/main.zeek
============================
.. zeek:namespace:: NTP


:Namespace: NTP

Summary
~~~~~~~
Redefinable Options
###################
=========================================================== =========================
:zeek:id:`NTP::ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for NTP.
=========================================================== =========================

Types
#####
================================================== ========================================================================
:zeek:type:`NTP::ControlInfo`: :zeek:type:`record` The record type which contains the column fields of the NTP control log.
:zeek:type:`NTP::Info`: :zeek:type:`record`
:zeek:type:`NTP::PrivateInfo`: :zeek:type:`record` The record type which contains the column fields of the NTP private log.
================================================== ========================================================================

Redefinitions
#############
============================================ ===================================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                             * :zeek:enum:`NTP::CONTROL_LOG`

                                             * :zeek:enum:`NTP::LOG`

                                             * :zeek:enum:`NTP::PRIVATE_LOG`
:zeek:type:`connection`: :zeek:type:`record`

                                             :New Fields: :zeek:type:`connection`

                                               ntp: :zeek:type:`NTP::Info` :zeek:attr:`&optional`

                                               ntp_control: :zeek:type:`NTP::ControlInfo` :zeek:attr:`&optional`

                                               ntp_private: :zeek:type:`NTP::PrivateInfo` :zeek:attr:`&optional`
============================================ ===================================================================

Events
######
=================================================== ===================================================================
:zeek:id:`NTP::log_ntp`: :zeek:type:`event`         Event that can be handled to access the NTP record as it is sent on
                                                    to the logging framework.
:zeek:id:`NTP::log_ntp_control`: :zeek:type:`event` Event that can be handled to access the NTP control record.
:zeek:id:`NTP::log_ntp_private`: :zeek:type:`event` Event that can be handled to access the NTP private record.
=================================================== ===================================================================

Hooks
#####
================================================================ =
:zeek:id:`NTP::log_policy`: :zeek:type:`Log::PolicyHook`
:zeek:id:`NTP::log_policy_control`: :zeek:type:`Log::PolicyHook`
:zeek:id:`NTP::log_policy_private`: :zeek:type:`Log::PolicyHook`
================================================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: NTP::ports
   :source-code: base/protocols/ntp/main.zeek 7 7

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            123/udp
         }


   Well-known ports for NTP.

Types
#####
.. zeek:type:: NTP::ControlInfo
   :source-code: base/protocols/ntp/main.zeek 56 87

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when the event happened.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: version :zeek:type:`count` :zeek:attr:`&log`

      The NTP version number (1, 2, 3, 4).


   .. zeek:field:: mode :zeek:type:`count` :zeek:attr:`&log`

      The NTP mode being used.


   .. zeek:field:: op_code :zeek:type:`count` :zeek:attr:`&log`

      The control operation code.


   .. zeek:field:: sequence :zeek:type:`count` :zeek:attr:`&log`

      The sequence number of the control message.


   .. zeek:field:: status :zeek:type:`count` :zeek:attr:`&log`

      The status word of the control response.


   .. zeek:field:: association_id :zeek:type:`count` :zeek:attr:`&log`

      The association ID.


   .. zeek:field:: resp_bit :zeek:type:`bool` :zeek:attr:`&log`

      The response bit.  Set to zero for commands, one for responses.


   .. zeek:field:: err_bit :zeek:type:`bool` :zeek:attr:`&log`

      The error bit.  Set to zero for normal response, one for error.


   .. zeek:field:: more_bit :zeek:type:`bool` :zeek:attr:`&log`

      The more bit.  Set to zero for last fragment, one for all others.


   .. zeek:field:: data :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The payload data of the control message.


   .. zeek:field:: key_id :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      The key ID used to generate the message-authentication code.


   .. zeek:field:: crypto_checksum :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The crypto-checksum computed by the encryption procedure.


   The record type which contains the column fields of the NTP control log.
   For more in-depth documentation, see :zeek:see:`NTP::ControlMessage`.

.. zeek:type:: NTP::Info
   :source-code: base/protocols/ntp/main.zeek 13 52

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when the event happened.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: version :zeek:type:`count` :zeek:attr:`&log`

      The NTP version number (1, 2, 3, 4).


   .. zeek:field:: mode :zeek:type:`count` :zeek:attr:`&log`

      The NTP mode being used.


   .. zeek:field:: stratum :zeek:type:`count` :zeek:attr:`&log`

      The stratum (primary server, secondary server, etc.).


   .. zeek:field:: poll :zeek:type:`interval` :zeek:attr:`&log`

      The maximum interval between successive messages.


   .. zeek:field:: precision :zeek:type:`interval` :zeek:attr:`&log`

      The precision of the system clock.


   .. zeek:field:: root_delay :zeek:type:`interval` :zeek:attr:`&log`

      Total round-trip delay to the reference clock.


   .. zeek:field:: root_disp :zeek:type:`interval` :zeek:attr:`&log`

      Total dispersion to the reference clock.


   .. zeek:field:: ref_id :zeek:type:`string` :zeek:attr:`&log`

      For stratum 0, 4 character string used for debugging.
      For stratum 1, ID assigned to the reference clock by IANA.
      Above stratum 1, when using IPv4, the IP address of the reference
      clock.  Note that the NTP protocol did not originally specify a
      large enough field to represent IPv6 addresses, so they use
      the first four bytes of the MD5 hash of the reference clock's
      IPv6 address (i.e. an IPv4 address here is not necessarily IPv4).


   .. zeek:field:: ref_time :zeek:type:`time` :zeek:attr:`&log`

      Time when the system clock was last set or correct.


   .. zeek:field:: org_time :zeek:type:`time` :zeek:attr:`&log`

      Time at the client when the request departed for the NTP server.


   .. zeek:field:: rec_time :zeek:type:`time` :zeek:attr:`&log`

      Time at the server when the request arrived from the NTP client.


   .. zeek:field:: xmt_time :zeek:type:`time` :zeek:attr:`&log`

      Time at the server when the response departed for the NTP client.


   .. zeek:field:: num_exts :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional` :zeek:attr:`&log`

      Number of extension fields (which are not currently parsed).



.. zeek:type:: NTP::PrivateInfo
   :source-code: base/protocols/ntp/main.zeek 91 114

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when the event happened.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: version :zeek:type:`count` :zeek:attr:`&log`

      The NTP version number (1, 2, 3, 4).


   .. zeek:field:: mode :zeek:type:`count` :zeek:attr:`&log`

      The NTP mode being used.


   .. zeek:field:: req_code :zeek:type:`count` :zeek:attr:`&log`

      The request code.


   .. zeek:field:: sequence :zeek:type:`count` :zeek:attr:`&log`

      The sequence number of the private message.


   .. zeek:field:: implementation :zeek:type:`count` :zeek:attr:`&log`

      The implementation number.


   .. zeek:field:: auth_bit :zeek:type:`bool` :zeek:attr:`&log`

      The authenticated bit.  If set, this packet is authenticated.


   .. zeek:field:: err :zeek:type:`count` :zeek:attr:`&log`

      The error code.


   .. zeek:field:: data :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The payload data of the private message.


   The record type which contains the column fields of the NTP private log.
   For more in-depth documentation, see :zeek:see:`NTP::Mode7Message`.

Events
######
.. zeek:id:: NTP::log_ntp
   :source-code: base/protocols/ntp/main.zeek 118 118

   :Type: :zeek:type:`event` (rec: :zeek:type:`NTP::Info`)

   Event that can be handled to access the NTP record as it is sent on
   to the logging framework.

.. zeek:id:: NTP::log_ntp_control
   :source-code: base/protocols/ntp/main.zeek 121 121

   :Type: :zeek:type:`event` (rec: :zeek:type:`NTP::ControlInfo`)

   Event that can be handled to access the NTP control record.

.. zeek:id:: NTP::log_ntp_private
   :source-code: base/protocols/ntp/main.zeek 124 124

   :Type: :zeek:type:`event` (rec: :zeek:type:`NTP::PrivateInfo`)

   Event that can be handled to access the NTP private record.

Hooks
#####
.. zeek:id:: NTP::log_policy
   :source-code: base/protocols/ntp/main.zeek 9 9

   :Type: :zeek:type:`Log::PolicyHook`


.. zeek:id:: NTP::log_policy_control
   :source-code: base/protocols/ntp/main.zeek 10 10

   :Type: :zeek:type:`Log::PolicyHook`


.. zeek:id:: NTP::log_policy_private
   :source-code: base/protocols/ntp/main.zeek 11 11

   :Type: :zeek:type:`Log::PolicyHook`



