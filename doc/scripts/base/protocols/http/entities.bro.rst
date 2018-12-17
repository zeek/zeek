:tocdepth: 3

base/protocols/http/entities.bro
================================
.. bro:namespace:: HTTP

Analysis and logging for MIME entities found in HTTP sessions.

:Namespace: HTTP
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/http/main.bro </scripts/base/protocols/http/main.bro>`, :doc:`base/utils/files.bro </scripts/base/utils/files.bro>`, :doc:`base/utils/strings.bro </scripts/base/utils/strings.bro>`

Summary
~~~~~~~
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


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: HTTP::Entity

   :Type: :bro:type:`record`

      filename: :bro:type:`string` :bro:attr:`&optional`
         Filename for the entity if discovered from a header.



