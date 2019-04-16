:tocdepth: 3

policy/protocols/smtp/blocklists.zeek
=====================================
.. bro:namespace:: SMTP

Watch for various SPAM blocklist URLs in SMTP error messages.

:Namespace: SMTP
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/smtp </scripts/base/protocols/smtp/index>`

Summary
~~~~~~~
Runtime Options
###############
================================================================================ =
:bro:id:`SMTP::blocklist_error_messages`: :bro:type:`pattern` :bro:attr:`&redef` 
================================================================================ =

Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: SMTP::blocklist_error_messages

   :Type: :bro:type:`pattern`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      /^?((^?((^?((^?((^?((^?((^?((^?((^?((^?((^?((^?((^?((^?((^?(spamhaus\.org\/)$?)|(^?(sophos\.com\/security\/)$?))$?)|(^?(spamcop\.net\/bl)$?))$?)|(^?(cbl\.abuseat\.org\/)$?))$?)|(^?(sorbs\.net\/)$?))$?)|(^?(bsn\.borderware\.com\/)$?))$?)|(^?(mail-abuse\.com\/)$?))$?)|(^?(b\.barracudacentral\.com\/)$?))$?)|(^?(psbl\.surriel\.com\/)$?))$?)|(^?(antispam\.imp\.ch\/)$?))$?)|(^?(dyndns\.com\/.*spam)$?))$?)|(^?(rbl\.knology\.net\/)$?))$?)|(^?(intercept\.datapacket\.net\/)$?))$?)|(^?(uceprotect\.net\/)$?))$?)|(^?(hostkarma\.junkemailfilter\.com\/)$?))$?/



