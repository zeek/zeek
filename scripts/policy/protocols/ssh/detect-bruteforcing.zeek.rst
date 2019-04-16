:tocdepth: 3

policy/protocols/ssh/detect-bruteforcing.zeek
=============================================
.. bro:namespace:: SSH

Detect hosts which are doing password guessing attacks and/or password
bruteforcing over SSH.

:Namespace: SSH
:Imports: :doc:`base/frameworks/intel </scripts/base/frameworks/intel/index>`, :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`, :doc:`base/protocols/ssh </scripts/base/protocols/ssh/index>`

Summary
~~~~~~~
Redefinable Options
###################
============================================================================ =====================================================================
:bro:id:`SSH::guessing_timeout`: :bro:type:`interval` :bro:attr:`&redef`     The amount of time to remember presumed non-successful logins to
                                                                             build a model of a password guesser.
:bro:id:`SSH::ignore_guessers`: :bro:type:`table` :bro:attr:`&redef`         This value can be used to exclude hosts or entire networks from being
                                                                             tracked as potential "guessers".
:bro:id:`SSH::password_guesses_limit`: :bro:type:`double` :bro:attr:`&redef` The number of failed SSH connections before a host is designated as
                                                                             guessing passwords.
============================================================================ =====================================================================

Redefinitions
#############
========================================== =
:bro:type:`Intel::Where`: :bro:type:`enum` 
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: SSH::guessing_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``30.0 mins``

   The amount of time to remember presumed non-successful logins to
   build a model of a password guesser.

.. bro:id:: SSH::ignore_guessers

   :Type: :bro:type:`table` [:bro:type:`subnet`] of :bro:type:`subnet`
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   This value can be used to exclude hosts or entire networks from being
   tracked as potential "guessers". The index represents
   client subnets and the yield value represents server subnets.

.. bro:id:: SSH::password_guesses_limit

   :Type: :bro:type:`double`
   :Attributes: :bro:attr:`&redef`
   :Default: ``30.0``

   The number of failed SSH connections before a host is designated as
   guessing passwords.


