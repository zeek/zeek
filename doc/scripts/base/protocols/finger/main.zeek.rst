:tocdepth: 3

base/protocols/finger/main.zeek
===============================
.. zeek:namespace:: Finger

Implements base functionality for Finger analysis. We currently do not generate
a log file, but just configure the analyzer.

:Namespace: Finger

Summary
~~~~~~~
Constants
#########
========================================== =
:zeek:id:`Finger::ports`: :zeek:type:`set` 
========================================== =

Redefinitions
#############
==================================================================== =
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: Finger::ports
   :source-code: base/protocols/finger/main.zeek 7 7

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Default:

      ::

         {
            79/tcp
         }




