:tocdepth: 3

policy/protocols/ftp/detect-bruteforcing.bro
============================================
.. bro:namespace:: FTP

FTP brute-forcing detector, triggering when too many rejected usernames or
failed passwords have occurred from a single address.

:Namespace: FTP
:Imports: :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`, :doc:`base/protocols/ftp </scripts/base/protocols/ftp/index>`, :doc:`base/utils/time.bro </scripts/base/utils/time.bro>`

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================= ==================================================================
:bro:id:`FTP::bruteforce_measurement_interval`: :bro:type:`interval` :bro:attr:`&redef` The time period in which the threshold needs to be crossed before
                                                                                        being reset.
:bro:id:`FTP::bruteforce_threshold`: :bro:type:`double` :bro:attr:`&redef`              How many rejected usernames or passwords are required before being
                                                                                        considered to be bruteforcing.
======================================================================================= ==================================================================

Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: FTP::bruteforce_measurement_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``15.0 mins``

   The time period in which the threshold needs to be crossed before
   being reset.

.. bro:id:: FTP::bruteforce_threshold

   :Type: :bro:type:`double`
   :Attributes: :bro:attr:`&redef`
   :Default: ``20.0``

   How many rejected usernames or passwords are required before being
   considered to be bruteforcing.


