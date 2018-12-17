:tocdepth: 3

base/protocols/smtp/entities.bro
================================
.. bro:namespace:: SMTP

Analysis and logging for MIME entities found in SMTP sessions.

:Namespace: SMTP
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/smtp/main.bro </scripts/base/protocols/smtp/main.bro>`, :doc:`base/utils/files.bro </scripts/base/utils/files.bro>`, :doc:`base/utils/strings.bro </scripts/base/utils/strings.bro>`

Summary
~~~~~~~
Types
#####
============================================ =
:bro:type:`SMTP::Entity`: :bro:type:`record` 
============================================ =

Redefinitions
#############
=========================================== =
:bro:type:`SMTP::Info`: :bro:type:`record`  
:bro:type:`SMTP::State`: :bro:type:`record` 
=========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: SMTP::Entity

   :Type: :bro:type:`record`

      filename: :bro:type:`string` :bro:attr:`&optional`
         Filename for the entity if discovered from a header.

      excerpt: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/smtp/entities-excerpt.bro` is loaded)

         The entity body excerpt.



