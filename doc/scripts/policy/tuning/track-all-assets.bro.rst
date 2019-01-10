:tocdepth: 3

policy/tuning/track-all-assets.bro
==================================


:Imports: :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`, :doc:`policy/protocols/conn/known-hosts.bro </scripts/policy/protocols/conn/known-hosts.bro>`, :doc:`policy/protocols/conn/known-services.bro </scripts/policy/protocols/conn/known-services.bro>`, :doc:`policy/protocols/ssl/known-certs.bro </scripts/policy/protocols/ssl/known-certs.bro>`

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

