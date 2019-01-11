:tocdepth: 3

policy/frameworks/files/detect-MHR.bro
======================================
.. bro:namespace:: TeamCymruMalwareHashRegistry

Detect file downloads that have hash values matching files in Team
Cymru's Malware Hash Registry (http://www.team-cymru.org/Services/MHR/).

:Namespace: TeamCymruMalwareHashRegistry
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`policy/frameworks/files/hash-all-files.bro </scripts/policy/frameworks/files/hash-all-files.bro>`

Summary
~~~~~~~
Runtime Options
###############
================================================================================================ ====================================================================
:bro:id:`TeamCymruMalwareHashRegistry::match_file_types`: :bro:type:`pattern` :bro:attr:`&redef` File types to attempt matching against the Malware Hash Registry.
:bro:id:`TeamCymruMalwareHashRegistry::match_sub_url`: :bro:type:`string` :bro:attr:`&redef`     The Match notice has a sub message with a URL where you can get more
                                                                                                 information about the file.
:bro:id:`TeamCymruMalwareHashRegistry::notice_threshold`: :bro:type:`count` :bro:attr:`&redef`   The malware hash registry runs each malware sample through several
                                                                                                 A/V engines.
================================================================================================ ====================================================================

Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: TeamCymruMalwareHashRegistry::match_file_types

   :Type: :bro:type:`pattern`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      /^?((^?((^?((^?((^?((^?((^?(application\/x-dosexec)$?)|(^?(application\/vnd.ms-cab-compressed)$?))$?)|(^?(application\/pdf)$?))$?)|(^?(application\/x-shockwave-flash)$?))$?)|(^?(application\/x-java-applet)$?))$?)|(^?(application\/jar)$?))$?)|(^?(video\/mp4)$?))$?/

   File types to attempt matching against the Malware Hash Registry.

.. bro:id:: TeamCymruMalwareHashRegistry::match_sub_url

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"https://www.virustotal.com/en/search/?query=%s"``

   The Match notice has a sub message with a URL where you can get more
   information about the file. The %s will be replaced with the SHA-1
   hash of the file.

.. bro:id:: TeamCymruMalwareHashRegistry::notice_threshold

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10``

   The malware hash registry runs each malware sample through several
   A/V engines.  Team Cymru returns a percentage to indicate how
   many A/V engines flagged the sample as malicious. This threshold
   allows you to require a minimum detection rate.


