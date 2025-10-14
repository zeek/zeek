:tocdepth: 3

base/bif/communityid.bif.zeek
=============================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
================================================= ================================================================
:zeek:id:`community_id_v1`: :zeek:type:`function` Compute the Community ID hash (v1) from a connection identifier.
================================================= ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: community_id_v1
   :source-code: base/bif/communityid.bif.zeek 12 12

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, seed: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`, do_base64: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`) : :zeek:type:`string`

   Compute the Community ID hash (v1) from a connection identifier.
   

   :param cid: The identifier of the connection for which to compute the community-id.
   

   :returns: The Community ID hash of the connection identifier as string.
   


