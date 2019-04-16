:tocdepth: 3

base/frameworks/signatures/main.zeek
====================================
.. bro:namespace:: Signatures

Script level signature support.  See the
:doc:`signature documentation </frameworks/signatures>` for more
information about Bro's signature engine.

:Namespace: Signatures
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`

Summary
~~~~~~~
Runtime Options
###############
=============================================================================== ===================================================================
:bro:id:`Signatures::ignored_ids`: :bro:type:`pattern` :bro:attr:`&redef`       Signature IDs that should always be ignored.
:bro:id:`Signatures::summary_interval`: :bro:type:`interval` :bro:attr:`&redef` The interval between when :bro:enum:`Signatures::Signature_Summary`
                                                                                notices are generated.
=============================================================================== ===================================================================

Redefinable Options
###################
========================================================================================================================================== ====================================================================
:bro:id:`Signatures::actions`: :bro:type:`table` :bro:attr:`&redef` :bro:attr:`&default` = ``Signatures::SIG_ALARM`` :bro:attr:`&optional` Actions for a signature.
:bro:id:`Signatures::count_thresholds`: :bro:type:`set` :bro:attr:`&redef`                                                                 Generate a notice if a :bro:enum:`Signatures::SIG_COUNT_PER_RESP`
                                                                                                                                           signature is triggered as often as given by one of these thresholds.
:bro:id:`Signatures::horiz_scan_thresholds`: :bro:type:`set` :bro:attr:`&redef`                                                            Generate a notice if, for a pair [orig, signature], the number of
                                                                                                                                           different responders has reached one of the thresholds.
:bro:id:`Signatures::vert_scan_thresholds`: :bro:type:`set` :bro:attr:`&redef`                                                             Generate a notice if, for a pair [orig, resp], the number of
                                                                                                                                           different signature matches has reached one of the thresholds.
========================================================================================================================================== ====================================================================

Types
#####
================================================ ======================================================================
:bro:type:`Signatures::Action`: :bro:type:`enum` These are the default actions you can apply to signature matches.
:bro:type:`Signatures::Info`: :bro:type:`record` The record type which contains the column fields of the signature log.
================================================ ======================================================================

Redefinitions
#############
========================================== ===========================================
:bro:type:`Log::ID`: :bro:type:`enum`      The signature logging stream identifier.
:bro:type:`Notice::Type`: :bro:type:`enum` Add various signature-related notice types.
========================================== ===========================================

Events
######
====================================================== =================================================================
:bro:id:`Signatures::log_signature`: :bro:type:`event` This event can be handled to access/alter data about to be logged
                                                       to the signature logging stream.
====================================================== =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Signatures::ignored_ids

   :Type: :bro:type:`pattern`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      /(^?(^?(^webapp-)$?)$?)|(^?((^?(^?(traceroute-detector.*)$?)$?)|(^?(^?(NO_DEFAULT_MATCHES)$?)$?))$?)/

   Signature IDs that should always be ignored.

.. bro:id:: Signatures::summary_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 day``

   The interval between when :bro:enum:`Signatures::Signature_Summary`
   notices are generated.

Redefinable Options
###################
.. bro:id:: Signatures::actions

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`Signatures::Action`
   :Attributes: :bro:attr:`&redef` :bro:attr:`&default` = ``Signatures::SIG_ALARM`` :bro:attr:`&optional`
   :Default:

   ::

      {
         ["unspecified"] = Signatures::SIG_IGNORE
      }

   Actions for a signature.  

.. bro:id:: Signatures::count_thresholds

   :Type: :bro:type:`set` [:bro:type:`count`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         500,
         1000,
         1000000,
         5,
         100,
         50,
         10000,
         10
      }

   Generate a notice if a :bro:enum:`Signatures::SIG_COUNT_PER_RESP`
   signature is triggered as often as given by one of these thresholds.

.. bro:id:: Signatures::horiz_scan_thresholds

   :Type: :bro:type:`set` [:bro:type:`count`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         500,
         1000,
         5,
         100,
         50,
         10
      }

   Generate a notice if, for a pair [orig, signature], the number of
   different responders has reached one of the thresholds.

.. bro:id:: Signatures::vert_scan_thresholds

   :Type: :bro:type:`set` [:bro:type:`count`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         500,
         1000,
         5,
         100,
         50,
         10
      }

   Generate a notice if, for a pair [orig, resp], the number of
   different signature matches has reached one of the thresholds.

Types
#####
.. bro:type:: Signatures::Action

   :Type: :bro:type:`enum`

      .. bro:enum:: Signatures::SIG_IGNORE Signatures::Action

         Ignore this signature completely (even for scan detection).
         Don't write to the signatures logging stream.

      .. bro:enum:: Signatures::SIG_QUIET Signatures::Action

         Process through the various aggregate techniques, but don't
         report individually and don't write to the signatures logging
         stream.

      .. bro:enum:: Signatures::SIG_LOG Signatures::Action

         Generate a notice.

      .. bro:enum:: Signatures::SIG_FILE_BUT_NO_SCAN Signatures::Action

         The same as :bro:enum:`Signatures::SIG_LOG`, but ignore for
         aggregate/scan processing.

      .. bro:enum:: Signatures::SIG_ALARM Signatures::Action

         Generate a notice and set it to be alarmed upon.

      .. bro:enum:: Signatures::SIG_ALARM_PER_ORIG Signatures::Action

         Alarm once per originator.

      .. bro:enum:: Signatures::SIG_ALARM_ONCE Signatures::Action

         Alarm once and then never again.

      .. bro:enum:: Signatures::SIG_COUNT_PER_RESP Signatures::Action

         Count signatures per responder host and alarm with the 
         :bro:enum:`Signatures::Count_Signature` notice if a threshold
         defined by :bro:id:`Signatures::count_thresholds` is reached.

      .. bro:enum:: Signatures::SIG_SUMMARY Signatures::Action

         Don't alarm, but generate per-orig summary.

   These are the default actions you can apply to signature matches.
   All of them write the signature record to the logging stream unless
   declared otherwise.

.. bro:type:: Signatures::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         The network time at which a signature matching type of event
         to be logged has occurred.

      uid: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         A unique identifier of the connection which triggered the
         signature match event.

      src_addr: :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&optional`
         The host which triggered the signature match event.

      src_port: :bro:type:`port` :bro:attr:`&log` :bro:attr:`&optional`
         The host port on which the signature-matching activity
         occurred.

      dst_addr: :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&optional`
         The destination host which was sent the payload that
         triggered the signature match.

      dst_port: :bro:type:`port` :bro:attr:`&log` :bro:attr:`&optional`
         The destination host port which was sent the payload that
         triggered the signature match.

      note: :bro:type:`Notice::Type` :bro:attr:`&log`
         Notice associated with signature event.

      sig_id: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The name of the signature that matched.

      event_msg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         A more descriptive message of the signature-matching event.

      sub_msg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Extracted payload data or extra message.

      sig_count: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Number of sigs, usually from summary count.

      host_count: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Number of hosts, from a summary count.

   The record type which contains the column fields of the signature log.

Events
######
.. bro:id:: Signatures::log_signature

   :Type: :bro:type:`event` (rec: :bro:type:`Signatures::Info`)

   This event can be handled to access/alter data about to be logged
   to the signature logging stream.
   

   :rec: The record of signature data about to be logged.


