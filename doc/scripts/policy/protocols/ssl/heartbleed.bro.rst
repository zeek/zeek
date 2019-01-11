:tocdepth: 3

policy/protocols/ssl/heartbleed.bro
===================================
.. bro:namespace:: Heartbleed

Detect the TLS heartbleed attack. See http://heartbleed.com for more.

:Namespace: Heartbleed
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
Redefinitions
#############
==================================================================================== =
:bro:type:`Notice::Type`: :bro:type:`enum`                                           
:bro:type:`SSL::Info`: :bro:type:`record`                                            
:bro:id:`SSL::disable_analyzer_after_detection`: :bro:type:`bool` :bro:attr:`&redef` 
==================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

