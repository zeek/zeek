:tocdepth: 3

policy/tuning/track-all-assets.zeek
===================================


:Imports: :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`, :doc:`policy/protocols/conn/known-hosts.zeek </scripts/policy/protocols/conn/known-hosts.zeek>`, :doc:`policy/protocols/conn/known-services.zeek </scripts/policy/protocols/conn/known-services.zeek>`, :doc:`policy/protocols/ssl/known-certs.zeek </scripts/policy/protocols/ssl/known-certs.zeek>`

Summary
~~~~~~~
Redefinitions
#############
========================================================================== =
:zeek:id:`Known::cert_tracking`: :zeek:type:`Host` :zeek:attr:`&redef`     
:zeek:id:`Known::host_tracking`: :zeek:type:`Host` :zeek:attr:`&redef`     
:zeek:id:`Known::service_tracking`: :zeek:type:`Host` :zeek:attr:`&redef`  
:zeek:id:`Software::asset_tracking`: :zeek:type:`Host` :zeek:attr:`&redef` 
========================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

