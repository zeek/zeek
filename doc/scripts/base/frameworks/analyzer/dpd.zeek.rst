:tocdepth: 3

base/frameworks/analyzer/dpd.zeek
=================================
.. zeek:namespace:: DPD

Disables analyzers if protocol violations occur, and adds service information
to connection log.

:Namespace: DPD
:Imports: :doc:`base/frameworks/analyzer/main.zeek </scripts/base/frameworks/analyzer/main.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================================================================================================ =========================================================================
:zeek:id:`DPD::ignore_violations`: :zeek:type:`set` :zeek:attr:`&redef`                                                                                      Analyzers which you don't want to remove on violations.
:zeek:id:`DPD::ignore_violations_after`: :zeek:type:`count` :zeek:attr:`&redef`                                                                              Ignore violations which go this many bytes into the connection.
:zeek:id:`DPD::max_violations`: :zeek:type:`table` :zeek:attr:`&deprecated` = *...* :zeek:attr:`&default` = ``5`` :zeek:attr:`&optional` :zeek:attr:`&redef` Deprecated, please see https://github.com/zeek/zeek/pull/4200 for details
:zeek:id:`DPD::track_removed_services_in_connection`: :zeek:type:`bool` :zeek:attr:`&redef`                                                                  Change behavior of service field in conn.log:
                                                                                                                                                             Failed services are no longer removed.
============================================================================================================================================================ =========================================================================

Redefinitions
#############
============================================ ==================================================================================================================
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               failed_analyzers: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
                                                 The set of prototol analyzers that were removed due to a protocol
                                                 violation after the same analyzer had previously been confirmed.
============================================ ==================================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: DPD::ignore_violations
   :source-code: base/frameworks/analyzer/dpd.zeek 13 13

   :Type: :zeek:type:`set` [:zeek:type:`Analyzer::Tag`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/protocols/dce-rpc/main.zeek`

      ``+=``::

         Analyzer::ANALYZER_DCE_RPC

   :Redefinition: from :doc:`/scripts/base/protocols/ntlm/main.zeek`

      ``+=``::

         Analyzer::ANALYZER_NTLM


   Analyzers which you don't want to remove on violations.

.. zeek:id:: DPD::ignore_violations_after
   :source-code: base/frameworks/analyzer/dpd.zeek 17 17

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10240``

   Ignore violations which go this many bytes into the connection.
   Set to 0 to never ignore protocol violations.

.. zeek:id:: DPD::max_violations
   :source-code: base/frameworks/analyzer/dpd.zeek 10 10

   :Type: :zeek:type:`table` [:zeek:type:`Analyzer::Tag`] of :zeek:type:`count`
   :Attributes: :zeek:attr:`&deprecated` = *"Remove in v8.1: This has become non-functional in Zeek 7.2, see PR #4200"* :zeek:attr:`&default` = ``5`` :zeek:attr:`&optional` :zeek:attr:`&redef`
   :Default: ``{}``

   Deprecated, please see https://github.com/zeek/zeek/pull/4200 for details

.. zeek:id:: DPD::track_removed_services_in_connection
   :source-code: base/frameworks/analyzer/dpd.zeek 24 24

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Change behavior of service field in conn.log:
   Failed services are no longer removed. Instead, for a failed
   service, a second entry with a "-" in front of it is added.
   E.g. a http connection with a violation would be logged as
   "http,-http".


