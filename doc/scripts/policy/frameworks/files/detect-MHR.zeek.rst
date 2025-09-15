:tocdepth: 3

policy/frameworks/files/detect-MHR.zeek
=======================================
.. zeek:namespace:: TeamCymruMalwareHashRegistry

Detect file downloads that have hash values matching files in Team
Cymru's Malware Hash Registry (https://www.team-cymru.com/mhr.html).

:Namespace: TeamCymruMalwareHashRegistry
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`policy/frameworks/files/hash-all-files.zeek </scripts/policy/frameworks/files/hash-all-files.zeek>`

Summary
~~~~~~~
Runtime Options
###############
=================================================================================================== ====================================================================
:zeek:id:`TeamCymruMalwareHashRegistry::match_file_types`: :zeek:type:`pattern` :zeek:attr:`&redef` File types to attempt matching against the Malware Hash Registry.
:zeek:id:`TeamCymruMalwareHashRegistry::match_sub_url`: :zeek:type:`string` :zeek:attr:`&redef`     The Match notice has a sub message with a URL where you can get more
                                                                                                    information about the file.
:zeek:id:`TeamCymruMalwareHashRegistry::notice_threshold`: :zeek:type:`count` :zeek:attr:`&redef`   The malware hash registry runs each malware sample through several
                                                                                                    A/V engines.
=================================================================================================== ====================================================================

Redefinitions
#############
============================================ ===============================================================
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`TeamCymruMalwareHashRegistry::Match`:
                                               The hash value of a file transferred over HTTP matched in the
                                               malware hash registry.
============================================ ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: TeamCymruMalwareHashRegistry::match_file_types
   :source-code: policy/frameworks/files/detect-MHR.zeek 18 18

   :Type: :zeek:type:`pattern`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         /^?((^?((^?((^?((^?((^?((^?(application\/x-dosexec)$?)|(^?(application\/vnd\.ms-cab-compressed)$?))$?)|(^?(application\/pdf)$?))$?)|(^?(application\/x-shockwave-flash)$?))$?)|(^?(application\/x-java-applet)$?))$?)|(^?(application\/jar)$?))$?)|(^?(video\/mp4)$?))$?/


   File types to attempt matching against the Malware Hash Registry.

.. zeek:id:: TeamCymruMalwareHashRegistry::match_sub_url
   :source-code: policy/frameworks/files/detect-MHR.zeek 29 29

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"https://www.virustotal.com/gui/search/%s"``

   The Match notice has a sub message with a URL where you can get more
   information about the file. The %s will be replaced with the SHA-1
   hash of the file.

.. zeek:id:: TeamCymruMalwareHashRegistry::notice_threshold
   :source-code: policy/frameworks/files/detect-MHR.zeek 35 35

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10``

   The malware hash registry runs each malware sample through several
   A/V engines.  Team Cymru returns a percentage to indicate how
   many A/V engines flagged the sample as malicious. This threshold
   allows you to require a minimum detection rate.


