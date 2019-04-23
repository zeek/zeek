:tocdepth: 3

policy/protocols/ftp/detect-bruteforcing.zeek
=============================================
.. zeek:namespace:: FTP

FTP brute-forcing detector, triggering when too many rejected usernames or
failed passwords have occurred from a single address.

:Namespace: FTP
:Imports: :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`, :doc:`base/protocols/ftp </scripts/base/protocols/ftp/index>`, :doc:`base/utils/time.zeek </scripts/base/utils/time.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
========================================================================================== ==================================================================
:zeek:id:`FTP::bruteforce_measurement_interval`: :zeek:type:`interval` :zeek:attr:`&redef` The time period in which the threshold needs to be crossed before
                                                                                           being reset.
:zeek:id:`FTP::bruteforce_threshold`: :zeek:type:`double` :zeek:attr:`&redef`              How many rejected usernames or passwords are required before being
                                                                                           considered to be bruteforcing.
========================================================================================== ==================================================================

Redefinitions
#############
============================================ =
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
============================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: FTP::bruteforce_measurement_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``15.0 mins``

   The time period in which the threshold needs to be crossed before
   being reset.

.. zeek:id:: FTP::bruteforce_threshold

   :Type: :zeek:type:`double`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``20.0``

   How many rejected usernames or passwords are required before being
   considered to be bruteforcing.


