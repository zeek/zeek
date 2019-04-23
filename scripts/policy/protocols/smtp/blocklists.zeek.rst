:tocdepth: 3

policy/protocols/smtp/blocklists.zeek
=====================================
.. zeek:namespace:: SMTP

Watch for various SPAM blocklist URLs in SMTP error messages.

:Namespace: SMTP
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/smtp </scripts/base/protocols/smtp/index>`

Summary
~~~~~~~
Runtime Options
###############
=================================================================================== =
:zeek:id:`SMTP::blocklist_error_messages`: :zeek:type:`pattern` :zeek:attr:`&redef` 
=================================================================================== =

Redefinitions
#############
============================================ =
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
============================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SMTP::blocklist_error_messages

   :Type: :zeek:type:`pattern`
   :Attributes: :zeek:attr:`&redef`
   :Default:

   ::

      /^?((^?((^?((^?((^?((^?((^?((^?((^?((^?((^?((^?((^?((^?((^?(spamhaus\.org\/)$?)|(^?(sophos\.com\/security\/)$?))$?)|(^?(spamcop\.net\/bl)$?))$?)|(^?(cbl\.abuseat\.org\/)$?))$?)|(^?(sorbs\.net\/)$?))$?)|(^?(bsn\.borderware\.com\/)$?))$?)|(^?(mail-abuse\.com\/)$?))$?)|(^?(b\.barracudacentral\.com\/)$?))$?)|(^?(psbl\.surriel\.com\/)$?))$?)|(^?(antispam\.imp\.ch\/)$?))$?)|(^?(dyndns\.com\/.*spam)$?))$?)|(^?(rbl\.knology\.net\/)$?))$?)|(^?(intercept\.datapacket\.net\/)$?))$?)|(^?(uceprotect\.net\/)$?))$?)|(^?(hostkarma\.junkemailfilter\.com\/)$?))$?/



