:tocdepth: 3

policy/frameworks/notice/community-id.zeek
==========================================
.. zeek:namespace:: CommunityID::Notice


:Namespace: CommunityID::Notice
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/conn </scripts/base/protocols/conn/index>`, :doc:`policy/protocols/conn/community-id-logging.zeek </scripts/policy/protocols/conn/community-id-logging.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================== =
:zeek:id:`CommunityID::Notice::enabled`: :zeek:type:`bool` :zeek:attr:`&redef` 
============================================================================== =

Redefinitions
#############
============================================== ============================================================================
:zeek:type:`Notice::Info`: :zeek:type:`record` 
                                               
                                               :New Fields: :zeek:type:`Notice::Info`
                                               
                                                 community_id: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
============================================== ============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: CommunityID::Notice::enabled
   :source-code: policy/frameworks/notice/community-id.zeek 14 14

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``



