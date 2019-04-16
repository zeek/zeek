:tocdepth: 3

base/bif/plugins/Bro_SteppingStone.events.bif.zeek
==================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=============================================== ==============================================
:bro:id:`stp_correlate_pair`: :bro:type:`event` Event internal to the stepping stone detector.
:bro:id:`stp_create_endp`: :bro:type:`event`    Deprecated.
:bro:id:`stp_remove_endp`: :bro:type:`event`    Event internal to the stepping stone detector.
:bro:id:`stp_remove_pair`: :bro:type:`event`    Event internal to the stepping stone detector.
:bro:id:`stp_resume_endp`: :bro:type:`event`    Event internal to the stepping stone detector.
=============================================== ==============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: stp_correlate_pair

   :Type: :bro:type:`event` (e1: :bro:type:`int`, e2: :bro:type:`int`)

   Event internal to the stepping stone detector.

.. bro:id:: stp_create_endp

   :Type: :bro:type:`event` (c: :bro:type:`connection`, e: :bro:type:`int`, is_orig: :bro:type:`bool`)

   Deprecated. Will be removed.

.. bro:id:: stp_remove_endp

   :Type: :bro:type:`event` (e: :bro:type:`int`)

   Event internal to the stepping stone detector.

.. bro:id:: stp_remove_pair

   :Type: :bro:type:`event` (e1: :bro:type:`int`, e2: :bro:type:`int`)

   Event internal to the stepping stone detector.

.. bro:id:: stp_resume_endp

   :Type: :bro:type:`event` (e: :bro:type:`int`)

   Event internal to the stepping stone detector.


