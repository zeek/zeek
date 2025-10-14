:tocdepth: 3

base/protocols/smtp/entities.zeek
=================================
.. zeek:namespace:: SMTP

Analysis and logging for MIME entities found in SMTP sessions.

:Namespace: SMTP
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/frameworks/notice/weird.zeek </scripts/base/frameworks/notice/weird.zeek>`, :doc:`base/protocols/smtp/main.zeek </scripts/base/protocols/smtp/main.zeek>`, :doc:`base/utils/files.zeek </scripts/base/utils/files.zeek>`, :doc:`base/utils/strings.zeek </scripts/base/utils/strings.zeek>`

Summary
~~~~~~~
Types
#####
============================================== =
:zeek:type:`SMTP::Entity`: :zeek:type:`record` 
============================================== =

Redefinitions
#############
============================================= =====================================================================================
:zeek:type:`SMTP::Info`: :zeek:type:`record`  
                                              
                                              :New Fields: :zeek:type:`SMTP::Info`
                                              
                                                entity: :zeek:type:`SMTP::Entity` :zeek:attr:`&optional`
                                                  The current entity being seen.
:zeek:type:`SMTP::State`: :zeek:type:`record` 
                                              
                                              :New Fields: :zeek:type:`SMTP::State`
                                              
                                                mime_depth: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                  Track the number of MIME encoded files transferred
                                                  during a session.
============================================= =====================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: SMTP::Entity
   :source-code: base/protocols/smtp/entities.zeek 12 15

   :Type: :zeek:type:`record`

      filename: :zeek:type:`string` :zeek:attr:`&optional`
         Filename for the entity if discovered from a header.

      excerpt: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/smtp/entities-excerpt.zeek` is loaded)

         The entity body excerpt.



