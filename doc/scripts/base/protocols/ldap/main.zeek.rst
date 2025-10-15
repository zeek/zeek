:tocdepth: 3

base/protocols/ldap/main.zeek
=============================
.. zeek:namespace:: LDAP


:Namespace: LDAP
:Imports: :doc:`base/frameworks/reporter </scripts/base/frameworks/reporter/index>`, :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/ldap/consts.zeek </scripts/base/protocols/ldap/consts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
===================================================================================== =================================================
:zeek:id:`LDAP::default_capture_password`: :zeek:type:`bool` :zeek:attr:`&redef`      Whether clear text passwords are captured or not.
:zeek:id:`LDAP::default_log_search_attributes`: :zeek:type:`bool` :zeek:attr:`&redef` Whether to log LDAP search attributes or not.
===================================================================================== =================================================

Redefinable Options
###################
================================================================ ==================================================
:zeek:id:`LDAP::ports_tcp`: :zeek:type:`set` :zeek:attr:`&redef` TCP ports which should be considered for analysis.
:zeek:id:`LDAP::ports_udp`: :zeek:type:`set` :zeek:attr:`&redef` UDP ports which should be considered for analysis.
================================================================ ==================================================

Types
#####
=================================================== =
:zeek:type:`LDAP::MessageInfo`: :zeek:type:`record` 
:zeek:type:`LDAP::SearchInfo`: :zeek:type:`record`  
:zeek:type:`LDAP::State`: :zeek:type:`record`       
=================================================== =

Redefinitions
#############
==================================================================== =======================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
                                                                     
                                                                     * :zeek:enum:`LDAP::LDAP_LOG`
                                                                     
                                                                     * :zeek:enum:`LDAP::LDAP_SEARCH_LOG`
:zeek:type:`connection`: :zeek:type:`record`                         
                                                                     
                                                                     :New Fields: :zeek:type:`connection`
                                                                     
                                                                       ldap: :zeek:type:`LDAP::State` :zeek:attr:`&optional`
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== =======================================================

Events
######
==================================================== =
:zeek:id:`LDAP::log_ldap`: :zeek:type:`event`        
:zeek:id:`LDAP::log_ldap_search`: :zeek:type:`event` 
==================================================== =

Hooks
#####
================================================================ ================================================
:zeek:id:`LDAP::finalize_ldap`: :zeek:type:`Conn::RemovalHook`   LDAP finalization hook.
:zeek:id:`LDAP::log_policy`: :zeek:type:`Log::PolicyHook`        Default logging policy hook for LDAP_LOG.
:zeek:id:`LDAP::log_policy_search`: :zeek:type:`Log::PolicyHook` Default logging policy hook for LDAP_SEARCH_LOG.
================================================================ ================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: LDAP::default_capture_password
   :source-code: base/protocols/ldap/main.zeek 20 20

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Whether clear text passwords are captured or not.

.. zeek:id:: LDAP::default_log_search_attributes
   :source-code: base/protocols/ldap/main.zeek 23 23

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Whether to log LDAP search attributes or not.

Redefinable Options
###################
.. zeek:id:: LDAP::ports_tcp
   :source-code: base/protocols/ldap/main.zeek 14 14

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            3268/tcp,
            389/tcp
         }


   TCP ports which should be considered for analysis.

.. zeek:id:: LDAP::ports_udp
   :source-code: base/protocols/ldap/main.zeek 17 17

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            389/udp
         }


   UDP ports which should be considered for analysis.

Types
#####
.. zeek:type:: LDAP::MessageInfo
   :source-code: base/protocols/ldap/main.zeek 37 67

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`

      uid: :zeek:type:`string` :zeek:attr:`&log`

      id: :zeek:type:`conn_id` :zeek:attr:`&log`

      message_id: :zeek:type:`int` :zeek:attr:`&log` :zeek:attr:`&optional`

      version: :zeek:type:`int` :zeek:attr:`&log` :zeek:attr:`&optional`

      opcode: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      result: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      diagnostic_message: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      object: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      argument: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`


.. zeek:type:: LDAP::SearchInfo
   :source-code: base/protocols/ldap/main.zeek 72 106

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`

      uid: :zeek:type:`string` :zeek:attr:`&log`

      id: :zeek:type:`conn_id` :zeek:attr:`&log`

      message_id: :zeek:type:`int` :zeek:attr:`&log` :zeek:attr:`&optional`

      scope: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      deref_aliases: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      base_object: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      result_count: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      result: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      diagnostic_message: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      filter: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      attributes: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`


.. zeek:type:: LDAP::State
   :source-code: base/protocols/ldap/main.zeek 108 111

   :Type: :zeek:type:`record`

      messages: :zeek:type:`table` [:zeek:type:`int`] of :zeek:type:`LDAP::MessageInfo` :zeek:attr:`&optional`

      searches: :zeek:type:`table` [:zeek:type:`int`] of :zeek:type:`LDAP::SearchInfo` :zeek:attr:`&optional`


Events
######
.. zeek:id:: LDAP::log_ldap
   :source-code: base/protocols/ldap/main.zeek 115 115

   :Type: :zeek:type:`event` (rec: :zeek:type:`LDAP::MessageInfo`)


.. zeek:id:: LDAP::log_ldap_search
   :source-code: base/protocols/ldap/main.zeek 116 116

   :Type: :zeek:type:`event` (rec: :zeek:type:`LDAP::SearchInfo`)


Hooks
#####
.. zeek:id:: LDAP::finalize_ldap
   :source-code: base/protocols/ldap/main.zeek 396 415

   :Type: :zeek:type:`Conn::RemovalHook`

   LDAP finalization hook.

.. zeek:id:: LDAP::log_policy
   :source-code: base/protocols/ldap/main.zeek 26 26

   :Type: :zeek:type:`Log::PolicyHook`

   Default logging policy hook for LDAP_LOG.

.. zeek:id:: LDAP::log_policy_search
   :source-code: base/protocols/ldap/main.zeek 29 29

   :Type: :zeek:type:`Log::PolicyHook`

   Default logging policy hook for LDAP_SEARCH_LOG.


