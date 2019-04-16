:tocdepth: 3

base/protocols/http/entities.zeek
=================================
.. bro:namespace:: HTTP

Analysis and logging for MIME entities found in HTTP sessions.

:Namespace: HTTP
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/http/main.zeek </scripts/base/protocols/http/main.zeek>`, :doc:`base/utils/files.zeek </scripts/base/utils/files.zeek>`, :doc:`base/utils/strings.zeek </scripts/base/utils/strings.zeek>`

Summary
~~~~~~~
Runtime Options
###############
==================================================================== ==========================================
:bro:id:`HTTP::max_files_orig`: :bro:type:`count` :bro:attr:`&redef` Maximum number of originator files to log.
:bro:id:`HTTP::max_files_resp`: :bro:type:`count` :bro:attr:`&redef` Maximum number of responder files to log.
==================================================================== ==========================================

Types
#####
============================================ =
:bro:type:`HTTP::Entity`: :bro:type:`record` 
============================================ =

Redefinitions
#############
========================================================== =
:bro:type:`HTTP::Info`: :bro:type:`record`                 
:bro:type:`fa_file`: :bro:type:`record` :bro:attr:`&redef` 
========================================================== =

Hooks
#####
================================================== ================================================================
:bro:id:`HTTP::max_files_policy`: :bro:type:`hook` Called when reaching the max number of files across a given HTTP
                                                   connection according to :bro:see:`HTTP::max_files_orig`
                                                   or :bro:see:`HTTP::max_files_resp`.
================================================== ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: HTTP::max_files_orig

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``15``

   Maximum number of originator files to log.
   :bro:see:`HTTP::max_files_policy` even is called once this
   limit is reached to determine if it's enforced.

.. bro:id:: HTTP::max_files_resp

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``15``

   Maximum number of responder files to log.
   :bro:see:`HTTP::max_files_policy` even is called once this
   limit is reached to determine if it's enforced.

Types
#####
.. bro:type:: HTTP::Entity

   :Type: :bro:type:`record`

      filename: :bro:type:`string` :bro:attr:`&optional`
         Filename for the entity if discovered from a header.


Hooks
#####
.. bro:id:: HTTP::max_files_policy

   :Type: :bro:type:`hook` (f: :bro:type:`fa_file`, is_orig: :bro:type:`bool`) : :bro:type:`bool`

   Called when reaching the max number of files across a given HTTP
   connection according to :bro:see:`HTTP::max_files_orig`
   or :bro:see:`HTTP::max_files_resp`.  Break from the hook
   early to signal that the file limit should not be applied.


