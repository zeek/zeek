:tocdepth: 3

base/frameworks/signatures/main.zeek
====================================
.. zeek:namespace:: Signatures

Script level signature support.  See the
:doc:`signature documentation </frameworks/signatures>` for more
information about Zeek's signature engine.

:Namespace: Signatures
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`

Summary
~~~~~~~
Runtime Options
###############
================================================================================== ====================================================================
:zeek:id:`Signatures::ignored_ids`: :zeek:type:`pattern` :zeek:attr:`&redef`       Signature IDs that should always be ignored.
:zeek:id:`Signatures::summary_interval`: :zeek:type:`interval` :zeek:attr:`&redef` The interval between when :zeek:enum:`Signatures::Signature_Summary`
                                                                                   notices are generated.
================================================================================== ====================================================================

Redefinable Options
###################
================================================================================== ====================================================================
:zeek:id:`Signatures::count_thresholds`: :zeek:type:`set` :zeek:attr:`&redef`      Generate a notice if a :zeek:enum:`Signatures::SIG_COUNT_PER_RESP`
                                                                                   signature is triggered as often as given by one of these thresholds.
:zeek:id:`Signatures::horiz_scan_thresholds`: :zeek:type:`set` :zeek:attr:`&redef` Generate a notice if, for a pair [orig, signature], the number of
                                                                                   different responders has reached one of the thresholds.
:zeek:id:`Signatures::vert_scan_thresholds`: :zeek:type:`set` :zeek:attr:`&redef`  Generate a notice if, for a pair [orig, resp], the number of
                                                                                   different signature matches has reached one of the thresholds.
================================================================================== ====================================================================

State Variables
###############
======================================================================================================================== ========================
:zeek:id:`Signatures::actions`: :zeek:type:`table` :zeek:attr:`&redef` :zeek:attr:`&default` = ``Signatures::SIG_ALARM`` Actions for a signature.
======================================================================================================================== ========================

Types
#####
================================================== ======================================================================
:zeek:type:`Signatures::Action`: :zeek:type:`enum` These are the default actions you can apply to signature matches.
:zeek:type:`Signatures::Info`: :zeek:type:`record` The record type which contains the column fields of the signature log.
================================================== ======================================================================

Redefinitions
#############
============================================ =============================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      The signature logging stream identifier.

                                             * :zeek:enum:`Signatures::LOG`
:zeek:type:`Notice::Type`: :zeek:type:`enum` Add various signature-related notice types.

                                             * :zeek:enum:`Signatures::Count_Signature`:
                                               The same signature has triggered multiple times for a host.

                                             * :zeek:enum:`Signatures::Multiple_Sig_Responders`:
                                               Host has triggered the same signature on multiple hosts as
                                               defined by the :zeek:id:`Signatures::horiz_scan_thresholds`
                                               variable.

                                             * :zeek:enum:`Signatures::Multiple_Signatures`:
                                               Host has triggered many signatures on the same host.

                                             * :zeek:enum:`Signatures::Sensitive_Signature`:
                                               Generic notice type for notice-worthy signature matches.

                                             * :zeek:enum:`Signatures::Signature_Summary`:
                                               Summarize the number of times a host triggered a signature.
============================================ =============================================================

Events
######
======================================================== =================================================================
:zeek:id:`Signatures::log_signature`: :zeek:type:`event` This event can be handled to access/alter data about to be logged
                                                         to the signature logging stream.
======================================================== =================================================================

Hooks
#####
=============================================================== =============================================
:zeek:id:`Signatures::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
=============================================================== =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Signatures::ignored_ids
   :source-code: base/frameworks/signatures/main.zeek 110 110

   :Type: :zeek:type:`pattern`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         /^?(NO_DEFAULT_MATCHES)$?/

   :Redefinition: from :doc:`/scripts/policy/misc/detect-traceroute/main.zeek`

      ``+=``::

         /^?(traceroute-detector.*)$?/

   :Redefinition: from :doc:`/scripts/policy/protocols/http/detect-webapps.zeek`

      ``+=``::

         /^?(^webapp-)$?/


   Signature IDs that should always be ignored.

.. zeek:id:: Signatures::summary_interval
   :source-code: base/frameworks/signatures/main.zeek 126 126

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 day``

   The interval between when :zeek:enum:`Signatures::Signature_Summary`
   notices are generated.

Redefinable Options
###################
.. zeek:id:: Signatures::count_thresholds
   :source-code: base/frameworks/signatures/main.zeek 122 122

   :Type: :zeek:type:`set` [:zeek:type:`count`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            1000,
            10000,
            500,
            5,
            10,
            100,
            50,
            1000000
         }


   Generate a notice if a :zeek:enum:`Signatures::SIG_COUNT_PER_RESP`
   signature is triggered as often as given by one of these thresholds.

.. zeek:id:: Signatures::horiz_scan_thresholds
   :source-code: base/frameworks/signatures/main.zeek 114 114

   :Type: :zeek:type:`set` [:zeek:type:`count`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            1000,
            500,
            5,
            10,
            100,
            50
         }


   Generate a notice if, for a pair [orig, signature], the number of
   different responders has reached one of the thresholds.

.. zeek:id:: Signatures::vert_scan_thresholds
   :source-code: base/frameworks/signatures/main.zeek 118 118

   :Type: :zeek:type:`set` [:zeek:type:`count`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            1000,
            500,
            5,
            10,
            100,
            50
         }


   Generate a notice if, for a pair [orig, resp], the number of
   different signature matches has reached one of the thresholds.

State Variables
###############
.. zeek:id:: Signatures::actions
   :source-code: base/frameworks/signatures/main.zeek 105 105

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Signatures::Action`
   :Attributes: :zeek:attr:`&redef` :zeek:attr:`&default` = ``Signatures::SIG_ALARM``
   :Default:

      ::

         {
            ["unspecified"] = Signatures::SIG_IGNORE
         }


   Actions for a signature.  Can be updated dynamically.

Types
#####
.. zeek:type:: Signatures::Action
   :source-code: base/frameworks/signatures/main.zeek 44 70

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Signatures::SIG_IGNORE Signatures::Action

         Ignore this signature completely (even for scan detection).
         Don't write to the signatures logging stream.

      .. zeek:enum:: Signatures::SIG_QUIET Signatures::Action

         Process through the various aggregate techniques, but don't
         report individually and don't write to the signatures logging
         stream.

      .. zeek:enum:: Signatures::SIG_LOG Signatures::Action

         Generate a notice.

      .. zeek:enum:: Signatures::SIG_FILE_BUT_NO_SCAN Signatures::Action

         The same as :zeek:enum:`Signatures::SIG_LOG`, but ignore for
         aggregate/scan processing.

      .. zeek:enum:: Signatures::SIG_ALARM Signatures::Action

         Generate a notice and set it to be alarmed upon.

      .. zeek:enum:: Signatures::SIG_ALARM_PER_ORIG Signatures::Action

         Alarm once per originator.

      .. zeek:enum:: Signatures::SIG_ALARM_ONCE Signatures::Action

         Alarm once and then never again.

      .. zeek:enum:: Signatures::SIG_COUNT_PER_RESP Signatures::Action

         Count signatures per responder host and alarm with the
         :zeek:enum:`Signatures::Count_Signature` notice if a threshold
         defined by :zeek:id:`Signatures::count_thresholds` is reached.

      .. zeek:enum:: Signatures::SIG_SUMMARY Signatures::Action

         Don't alarm, but generate per-orig summary.

   These are the default actions you can apply to signature matches.
   All of them write the signature record to the logging stream unless
   declared otherwise.

.. zeek:type:: Signatures::Info
   :source-code: base/frameworks/signatures/main.zeek 72 102

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      The network time at which a signature matching type of event
      to be logged has occurred.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      A unique identifier of the connection which triggered the
      signature match event.


   .. zeek:field:: src_addr :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&optional`

      The host which triggered the signature match event.


   .. zeek:field:: src_port :zeek:type:`port` :zeek:attr:`&log` :zeek:attr:`&optional`

      The host port on which the signature-matching activity
      occurred.


   .. zeek:field:: dst_addr :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&optional`

      The destination host which was sent the payload that
      triggered the signature match.


   .. zeek:field:: dst_port :zeek:type:`port` :zeek:attr:`&log` :zeek:attr:`&optional`

      The destination host port which was sent the payload that
      triggered the signature match.


   .. zeek:field:: note :zeek:type:`Notice::Type` :zeek:attr:`&log`

      Notice associated with signature event.


   .. zeek:field:: sig_id :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The name of the signature that matched.


   .. zeek:field:: event_msg :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      A more descriptive message of the signature-matching event.


   .. zeek:field:: sub_msg :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Extracted payload data or extra message.


   .. zeek:field:: sig_count :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Number of sigs, usually from summary count.


   .. zeek:field:: host_count :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Number of hosts, from a summary count.


   The record type which contains the column fields of the signature log.

Events
######
.. zeek:id:: Signatures::log_signature
   :source-code: base/frameworks/signatures/main.zeek 132 132

   :Type: :zeek:type:`event` (rec: :zeek:type:`Signatures::Info`)

   This event can be handled to access/alter data about to be logged
   to the signature logging stream.


   :param rec: The record of signature data about to be logged.

Hooks
#####
.. zeek:id:: Signatures::log_policy
   :source-code: base/frameworks/signatures/main.zeek 39 39

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


