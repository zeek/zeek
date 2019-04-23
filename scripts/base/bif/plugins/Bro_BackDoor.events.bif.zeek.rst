:tocdepth: 3

base/bif/plugins/Bro_BackDoor.events.bif.zeek
=============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================= ===========
:zeek:id:`backdoor_remove_conn`: :zeek:type:`event`       Deprecated.
:zeek:id:`backdoor_stats`: :zeek:type:`event`             Deprecated.
:zeek:id:`ftp_signature_found`: :zeek:type:`event`        Deprecated.
:zeek:id:`gnutella_signature_found`: :zeek:type:`event`   Deprecated.
:zeek:id:`http_proxy_signature_found`: :zeek:type:`event` Deprecated.
:zeek:id:`http_signature_found`: :zeek:type:`event`       Deprecated.
:zeek:id:`irc_signature_found`: :zeek:type:`event`        Deprecated.
:zeek:id:`rlogin_signature_found`: :zeek:type:`event`     Deprecated.
:zeek:id:`smtp_signature_found`: :zeek:type:`event`       Deprecated.
:zeek:id:`ssh_signature_found`: :zeek:type:`event`        Deprecated.
:zeek:id:`telnet_signature_found`: :zeek:type:`event`     Deprecated.
========================================================= ===========


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: backdoor_remove_conn

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Deprecated. Will be removed.

.. zeek:id:: backdoor_stats

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, os: :zeek:type:`backdoor_endp_stats`, rs: :zeek:type:`backdoor_endp_stats`)

   Deprecated. Will be removed.

.. zeek:id:: ftp_signature_found

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Deprecated. Will be removed.

.. zeek:id:: gnutella_signature_found

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Deprecated. Will be removed.

.. zeek:id:: http_proxy_signature_found

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Deprecated. Will be removed.

.. zeek:id:: http_signature_found

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Deprecated. Will be removed.

.. zeek:id:: irc_signature_found

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Deprecated. Will be removed.

.. zeek:id:: rlogin_signature_found

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, num_null: :zeek:type:`count`, len: :zeek:type:`count`)

   Deprecated. Will be removed.

.. zeek:id:: smtp_signature_found

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Deprecated. Will be removed.

.. zeek:id:: ssh_signature_found

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Deprecated. Will be removed.

.. zeek:id:: telnet_signature_found

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, len: :zeek:type:`count`)

   Deprecated. Will be removed.


