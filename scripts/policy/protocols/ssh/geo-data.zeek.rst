:tocdepth: 3

policy/protocols/ssh/geo-data.zeek
==================================
.. bro:namespace:: SSH

Geodata based detections for SSH analysis.

:Namespace: SSH
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/ssh </scripts/base/protocols/ssh/index>`

Summary
~~~~~~~
Runtime Options
###############
==================================================================== ==================================================================
:bro:id:`SSH::watched_countries`: :bro:type:`set` :bro:attr:`&redef` The set of countries for which you'd like to generate notices upon
                                                                     successful login.
==================================================================== ==================================================================

Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
:bro:type:`SSH::Info`: :bro:type:`record`  
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: SSH::watched_countries

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         "RO"
      }

   The set of countries for which you'd like to generate notices upon
   successful login.


