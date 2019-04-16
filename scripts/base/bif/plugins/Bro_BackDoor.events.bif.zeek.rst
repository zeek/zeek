:tocdepth: 3

base/bif/plugins/Bro_BackDoor.events.bif.zeek
=============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================= ===========
:bro:id:`backdoor_remove_conn`: :bro:type:`event`       Deprecated.
:bro:id:`backdoor_stats`: :bro:type:`event`             Deprecated.
:bro:id:`ftp_signature_found`: :bro:type:`event`        Deprecated.
:bro:id:`gnutella_signature_found`: :bro:type:`event`   Deprecated.
:bro:id:`http_proxy_signature_found`: :bro:type:`event` Deprecated.
:bro:id:`http_signature_found`: :bro:type:`event`       Deprecated.
:bro:id:`irc_signature_found`: :bro:type:`event`        Deprecated.
:bro:id:`rlogin_signature_found`: :bro:type:`event`     Deprecated.
:bro:id:`smtp_signature_found`: :bro:type:`event`       Deprecated.
:bro:id:`ssh_signature_found`: :bro:type:`event`        Deprecated.
:bro:id:`telnet_signature_found`: :bro:type:`event`     Deprecated.
======================================================= ===========


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: backdoor_remove_conn

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Deprecated. Will be removed.

.. bro:id:: backdoor_stats

   :Type: :bro:type:`event` (c: :bro:type:`connection`, os: :bro:type:`backdoor_endp_stats`, rs: :bro:type:`backdoor_endp_stats`)

   Deprecated. Will be removed.

.. bro:id:: ftp_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Deprecated. Will be removed.

.. bro:id:: gnutella_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Deprecated. Will be removed.

.. bro:id:: http_proxy_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Deprecated. Will be removed.

.. bro:id:: http_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Deprecated. Will be removed.

.. bro:id:: irc_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Deprecated. Will be removed.

.. bro:id:: rlogin_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, num_null: :bro:type:`count`, len: :bro:type:`count`)

   Deprecated. Will be removed.

.. bro:id:: smtp_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Deprecated. Will be removed.

.. bro:id:: ssh_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   Deprecated. Will be removed.

.. bro:id:: telnet_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, len: :bro:type:`count`)

   Deprecated. Will be removed.


