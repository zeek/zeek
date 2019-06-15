:tocdepth: 3

base/bif/plugins/Zeek_SteppingStone.events.bif.zeek
===================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================= ==============================================
:zeek:id:`stp_correlate_pair`: :zeek:type:`event` Event internal to the stepping stone detector.
:zeek:id:`stp_create_endp`: :zeek:type:`event`    Deprecated.
:zeek:id:`stp_remove_endp`: :zeek:type:`event`    Event internal to the stepping stone detector.
:zeek:id:`stp_remove_pair`: :zeek:type:`event`    Event internal to the stepping stone detector.
:zeek:id:`stp_resume_endp`: :zeek:type:`event`    Event internal to the stepping stone detector.
================================================= ==============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: stp_correlate_pair

   :Type: :zeek:type:`event` (e1: :zeek:type:`int`, e2: :zeek:type:`int`)

   Event internal to the stepping stone detector.

.. zeek:id:: stp_create_endp

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, e: :zeek:type:`int`, is_orig: :zeek:type:`bool`)

   Deprecated. Will be removed.

.. zeek:id:: stp_remove_endp

   :Type: :zeek:type:`event` (e: :zeek:type:`int`)

   Event internal to the stepping stone detector.

.. zeek:id:: stp_remove_pair

   :Type: :zeek:type:`event` (e1: :zeek:type:`int`, e2: :zeek:type:`int`)

   Event internal to the stepping stone detector.

.. zeek:id:: stp_resume_endp

   :Type: :zeek:type:`event` (e: :zeek:type:`int`)

   Event internal to the stepping stone detector.


