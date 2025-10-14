:tocdepth: 3

base/protocols/ntp/main.zeek
============================
.. zeek:namespace:: NTP


:Namespace: NTP

Summary
~~~~~~~
Types
#####
=========================================== =
:zeek:type:`NTP::Info`: :zeek:type:`record` 
=========================================== =

Redefinitions
#############
==================================================================== ====================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
                                                                     
                                                                     * :zeek:enum:`NTP::LOG`
:zeek:type:`connection`: :zeek:type:`record`                         
                                                                     
                                                                     :New Fields: :zeek:type:`connection`
                                                                     
                                                                       ntp: :zeek:type:`NTP::Info` :zeek:attr:`&optional`
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== ====================================================

Events
######
=========================================== ===================================================================
:zeek:id:`NTP::log_ntp`: :zeek:type:`event` Event that can be handled to access the NTP record as it is sent on
                                            to the logging framework.
=========================================== ===================================================================

Hooks
#####
======================================================== =
:zeek:id:`NTP::log_policy`: :zeek:type:`Log::PolicyHook` 
======================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: NTP::Info
   :source-code: base/protocols/ntp/main.zeek 8 47

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp for when the event happened.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      version: :zeek:type:`count` :zeek:attr:`&log`
         The NTP version number (1, 2, 3, 4).

      mode: :zeek:type:`count` :zeek:attr:`&log`
         The NTP mode being used.

      stratum: :zeek:type:`count` :zeek:attr:`&log`
         The stratum (primary server, secondary server, etc.).

      poll: :zeek:type:`interval` :zeek:attr:`&log`
         The maximum interval between successive messages.

      precision: :zeek:type:`interval` :zeek:attr:`&log`
         The precision of the system clock.

      root_delay: :zeek:type:`interval` :zeek:attr:`&log`
         Total round-trip delay to the reference clock.

      root_disp: :zeek:type:`interval` :zeek:attr:`&log`
         Total dispersion to the reference clock.

      ref_id: :zeek:type:`string` :zeek:attr:`&log`
         For stratum 0, 4 character string used for debugging.
         For stratum 1, ID assigned to the reference clock by IANA.
         Above stratum 1, when using IPv4, the IP address of the reference
         clock.  Note that the NTP protocol did not originally specify a
         large enough field to represent IPv6 addresses, so they use
         the first four bytes of the MD5 hash of the reference clock's
         IPv6 address (i.e. an IPv4 address here is not necessarily IPv4).

      ref_time: :zeek:type:`time` :zeek:attr:`&log`
         Time when the system clock was last set or correct.

      org_time: :zeek:type:`time` :zeek:attr:`&log`
         Time at the client when the request departed for the NTP server.

      rec_time: :zeek:type:`time` :zeek:attr:`&log`
         Time at the server when the request arrived from the NTP client.

      xmt_time: :zeek:type:`time` :zeek:attr:`&log`
         Time at the server when the response departed for the NTP client.

      num_exts: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional` :zeek:attr:`&log`
         Number of extension fields (which are not currently parsed).


Events
######
.. zeek:id:: NTP::log_ntp
   :source-code: base/protocols/ntp/main.zeek 51 51

   :Type: :zeek:type:`event` (rec: :zeek:type:`NTP::Info`)

   Event that can be handled to access the NTP record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: NTP::log_policy
   :source-code: base/protocols/ntp/main.zeek 6 6

   :Type: :zeek:type:`Log::PolicyHook`



