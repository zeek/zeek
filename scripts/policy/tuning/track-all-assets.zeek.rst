:tocdepth: 3

policy/tuning/track-all-assets.zeek
===================================


:Imports: :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`, :doc:`policy/protocols/conn/known-hosts.zeek </scripts/policy/protocols/conn/known-hosts.zeek>`, :doc:`policy/protocols/conn/known-services.zeek </scripts/policy/protocols/conn/known-services.zeek>`, :doc:`policy/protocols/ssl/known-certs.zeek </scripts/policy/protocols/ssl/known-certs.zeek>`

Summary
~~~~~~~
Redefinitions
#############
======================================================================= =
:bro:id:`Known::cert_tracking`: :bro:type:`Host` :bro:attr:`&redef`     
:bro:id:`Known::host_tracking`: :bro:type:`Host` :bro:attr:`&redef`     
:bro:id:`Known::service_tracking`: :bro:type:`Host` :bro:attr:`&redef`  
:bro:id:`Software::asset_tracking`: :bro:type:`Host` :bro:attr:`&redef` 
======================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~

