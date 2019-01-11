:tocdepth: 3

policy/protocols/smtp/detect-suspicious-orig.bro
================================================
.. bro:namespace:: SMTP


:Namespace: SMTP
:Imports: :doc:`base/frameworks/notice/main.bro </scripts/base/frameworks/notice/main.bro>`, :doc:`base/protocols/smtp/main.bro </scripts/base/protocols/smtp/main.bro>`

Summary
~~~~~~~
Runtime Options
###############
==================================================================================== ===================================================================
:bro:id:`SMTP::suspicious_origination_countries`: :bro:type:`set` :bro:attr:`&redef` Places where it's suspicious for mail to originate from represented
                                                                                     as all-capital, two character country codes (e.g., US).
:bro:id:`SMTP::suspicious_origination_networks`: :bro:type:`set` :bro:attr:`&redef`  
==================================================================================== ===================================================================

Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: SMTP::suspicious_origination_countries

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Places where it's suspicious for mail to originate from represented
   as all-capital, two character country codes (e.g., US).  It requires
   Bro to be built with GeoIP support.

.. bro:id:: SMTP::suspicious_origination_networks

   :Type: :bro:type:`set` [:bro:type:`subnet`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``



