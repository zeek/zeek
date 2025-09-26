:tocdepth: 3

policy/protocols/conn/community-id-logging.zeek
===============================================
.. zeek:namespace:: CommunityID

Adds community hash IDs to conn.log.

:Namespace: CommunityID
:Imports: :doc:`base/protocols/conn </scripts/base/protocols/conn/index>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================== =
:zeek:id:`CommunityID::do_base64`: :zeek:type:`bool` :zeek:attr:`&redef` 
:zeek:id:`CommunityID::seed`: :zeek:type:`count` :zeek:attr:`&redef`     
======================================================================== =

Redefinitions
#############
============================================ ============================================================================
:zeek:type:`Conn::Info`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`Conn::Info`
                                             
                                               community_id: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
============================================ ============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: CommunityID::do_base64
   :source-code: policy/protocols/conn/community-id-logging.zeek 12 12

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``


.. zeek:id:: CommunityID::seed
   :source-code: policy/protocols/conn/community-id-logging.zeek 8 8

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0``



