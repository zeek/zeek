:tocdepth: 3

policy/protocols/ssh/detect-bruteforcing.zeek
=============================================
.. zeek:namespace:: SSH

Detect hosts which are doing password guessing attacks and/or password
bruteforcing over SSH.

:Namespace: SSH
:Imports: :doc:`base/frameworks/intel </scripts/base/frameworks/intel/index>`, :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`, :doc:`base/protocols/ssh </scripts/base/protocols/ssh/index>`

Summary
~~~~~~~
Redefinable Options
###################
=============================================================================== =====================================================================
:zeek:id:`SSH::guessing_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`     The amount of time to remember presumed non-successful logins to
                                                                                build a model of a password guesser.
:zeek:id:`SSH::ignore_guessers`: :zeek:type:`table` :zeek:attr:`&redef`         This value can be used to exclude hosts or entire networks from being
                                                                                tracked as potential "guessers".
:zeek:id:`SSH::password_guesses_limit`: :zeek:type:`double` :zeek:attr:`&redef` The number of failed SSH connections before a host is designated as
                                                                                guessing passwords.
=============================================================================== =====================================================================

Redefinitions
#############
============================================ =
:zeek:type:`Intel::Where`: :zeek:type:`enum` 
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
============================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: SSH::guessing_timeout

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``30.0 mins``

   The amount of time to remember presumed non-successful logins to
   build a model of a password guesser.

.. zeek:id:: SSH::ignore_guessers

   :Type: :zeek:type:`table` [:zeek:type:`subnet`] of :zeek:type:`subnet`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   This value can be used to exclude hosts or entire networks from being
   tracked as potential "guessers". The index represents
   client subnets and the yield value represents server subnets.

.. zeek:id:: SSH::password_guesses_limit

   :Type: :zeek:type:`double`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``30.0``

   The number of failed SSH connections before a host is designated as
   guessing passwords.


