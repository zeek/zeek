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
============================================ =====================================================================================
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`SSH::Watched_Country_Login`:
                                               If an SSH login is seen to or from a "watched" country based
                                               on the :zeek:id:`SSH::watched_countries` variable then this
                                               notice will be generated.
:zeek:type:`SSH::Info`: :zeek:type:`record`  
                                             
                                             :New Fields: :zeek:type:`SSH::Info`
                                             
                                               remote_location: :zeek:type:`geo_location` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 Add geographic data related to the "remote" host of the
                                                 connection.
============================================ =====================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SSH::watched_countries
   :source-code: policy/protocols/ssh/geo-data.zeek 24 24

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "RO"
         }


   The set of countries for which you'd like to generate notices upon
   successful login.


