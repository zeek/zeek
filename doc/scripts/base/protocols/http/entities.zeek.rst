:tocdepth: 3

base/protocols/http/entities.zeek
=================================
.. zeek:namespace:: HTTP

Analysis and logging for MIME entities found in HTTP sessions.

:Namespace: HTTP
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/frameworks/notice/weird.zeek </scripts/base/frameworks/notice/weird.zeek>`, :doc:`base/protocols/http/main.zeek </scripts/base/protocols/http/main.zeek>`, :doc:`base/utils/files.zeek </scripts/base/utils/files.zeek>`, :doc:`base/utils/strings.zeek </scripts/base/utils/strings.zeek>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================= ==========================================
:zeek:id:`HTTP::max_files_orig`: :zeek:type:`count` :zeek:attr:`&redef` Maximum number of originator files to log.
:zeek:id:`HTTP::max_files_resp`: :zeek:type:`count` :zeek:attr:`&redef` Maximum number of responder files to log.
======================================================================= ==========================================

Types
#####
============================================== =
:zeek:type:`HTTP::Entity`: :zeek:type:`record` 
============================================== =

Redefinitions
#############
============================================================= ======================================================================================================
:zeek:type:`HTTP::Info`: :zeek:type:`record`                  
                                                              
                                                              :New Fields: :zeek:type:`HTTP::Info`
                                                              
                                                                orig_fuids: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                  An ordered vector of file unique IDs.
                                                              
                                                                orig_filenames: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                  An ordered vector of filenames from the client.
                                                              
                                                                orig_mime_types: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                  An ordered vector of mime types.
                                                              
                                                                resp_fuids: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                  An ordered vector of file unique IDs.
                                                              
                                                                resp_filenames: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                  An ordered vector of filenames from the server.
                                                              
                                                                resp_mime_types: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                  An ordered vector of mime types.
                                                              
                                                                current_entity: :zeek:type:`HTTP::Entity` :zeek:attr:`&optional`
                                                                  The current entity.
                                                              
                                                                orig_mime_depth: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                                  Current number of MIME entities in the HTTP request message
                                                                  body.
                                                              
                                                                resp_mime_depth: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                                  Current number of MIME entities in the HTTP response message
                                                                  body.
:zeek:type:`fa_file`: :zeek:type:`record` :zeek:attr:`&redef` 
                                                              
                                                              :New Fields: :zeek:type:`fa_file`
                                                              
                                                                http: :zeek:type:`HTTP::Info` :zeek:attr:`&optional`
============================================================= ======================================================================================================

Hooks
#####
==================================================== ================================================================
:zeek:id:`HTTP::max_files_policy`: :zeek:type:`hook` Called when reaching the max number of files across a given HTTP
                                                     connection according to :zeek:see:`HTTP::max_files_orig`
                                                     or :zeek:see:`HTTP::max_files_resp`.
==================================================== ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: HTTP::max_files_orig
   :source-code: base/protocols/http/entities.zeek 20 20

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``15``

   Maximum number of originator files to log.
   :zeek:see:`HTTP::max_files_policy` even is called once this
   limit is reached to determine if it's enforced.

.. zeek:id:: HTTP::max_files_resp
   :source-code: base/protocols/http/entities.zeek 25 25

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``15``

   Maximum number of responder files to log.
   :zeek:see:`HTTP::max_files_policy` even is called once this
   limit is reached to determine if it's enforced.

Types
#####
.. zeek:type:: HTTP::Entity
   :source-code: base/protocols/http/entities.zeek 12 15

   :Type: :zeek:type:`record`

      filename: :zeek:type:`string` :zeek:attr:`&optional`
         Filename for the entity if discovered from a header.


Hooks
#####
.. zeek:id:: HTTP::max_files_policy
   :source-code: base/protocols/http/entities.zeek 31 31

   :Type: :zeek:type:`hook` (f: :zeek:type:`fa_file`, is_orig: :zeek:type:`bool`) : :zeek:type:`bool`

   Called when reaching the max number of files across a given HTTP
   connection according to :zeek:see:`HTTP::max_files_orig`
   or :zeek:see:`HTTP::max_files_resp`.  Break from the hook
   early to signal that the file limit should not be applied.


