:tocdepth: 3

policy/protocols/smtp/detect-suspicious-orig.zeek
=================================================
.. zeek:namespace:: SMTP


:Namespace: SMTP
:Imports: :doc:`base/frameworks/notice/main.zeek </scripts/base/frameworks/notice/main.zeek>`, :doc:`base/protocols/smtp/main.zeek </scripts/base/protocols/smtp/main.zeek>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================================= ===================================================================
:zeek:id:`SMTP::suspicious_origination_countries`: :zeek:type:`set` :zeek:attr:`&redef` Places where it's suspicious for mail to originate from represented
                                                                                        as all-capital, two character country codes (e.g., US).
:zeek:id:`SMTP::suspicious_origination_networks`: :zeek:type:`set` :zeek:attr:`&redef`  
======================================================================================= ===================================================================

Redefinitions
#############
============================================ ===========================================
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`SMTP::Suspicious_Origination`
============================================ ===========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SMTP::suspicious_origination_countries
   :source-code: policy/protocols/smtp/detect-suspicious-orig.zeek 14 14

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Places where it's suspicious for mail to originate from represented
   as all-capital, two character country codes (e.g., US).  It requires
   Zeek to be built with GeoIP support.

.. zeek:id:: SMTP::suspicious_origination_networks
   :source-code: policy/protocols/smtp/detect-suspicious-orig.zeek 15 15

   :Type: :zeek:type:`set` [:zeek:type:`subnet`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``



