:tocdepth: 3

policy/protocols/ssl/heartbleed.zeek
====================================
.. zeek:namespace:: Heartbleed

Detect the TLS heartbleed attack. See http://heartbleed.com for more.

:Namespace: Heartbleed
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
Redefinitions
#############
======================================================================================= =
:zeek:type:`Notice::Type`: :zeek:type:`enum`                                            
:zeek:type:`SSL::Info`: :zeek:type:`record`                                             
:zeek:id:`SSL::disable_analyzer_after_detection`: :zeek:type:`bool` :zeek:attr:`&redef` 
======================================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~

