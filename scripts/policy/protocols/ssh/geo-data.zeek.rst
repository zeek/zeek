:tocdepth: 3

policy/protocols/ssh/geo-data.zeek
==================================
.. zeek:namespace:: SSH

Geodata based detections for SSH analysis.

:Namespace: SSH
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/ssh </scripts/base/protocols/ssh/index>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================= ==================================================================
:zeek:id:`SSH::watched_countries`: :zeek:type:`set` :zeek:attr:`&redef` The set of countries for which you'd like to generate notices upon
                                                                        successful login.
======================================================================= ==================================================================

Redefinitions
#############
============================================ =
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
:zeek:type:`SSH::Info`: :zeek:type:`record`  
============================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SSH::watched_countries

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "RO"
         }


   The set of countries for which you'd like to generate notices upon
   successful login.


