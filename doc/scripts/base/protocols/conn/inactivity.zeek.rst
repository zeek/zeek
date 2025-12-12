:tocdepth: 3

base/protocols/conn/inactivity.zeek
===================================
.. zeek:namespace:: Conn

Adjust the inactivity timeouts for interactive services which could
very possibly have long delays between packets.

:Namespace: Conn

Summary
~~~~~~~
Runtime Options
###############
===================================================================================== ==================================================================
:zeek:id:`Conn::analyzer_inactivity_timeouts`: :zeek:type:`table` :zeek:attr:`&redef` Define inactivity timeouts by the service detected being used over
                                                                                      the connection.
:zeek:id:`Conn::port_inactivity_timeouts`: :zeek:type:`table` :zeek:attr:`&redef`     Define inactivity timeouts based on common protocol ports.
===================================================================================== ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Conn::analyzer_inactivity_timeouts
   :source-code: base/protocols/conn/inactivity.zeek 9 9

   :Type: :zeek:type:`table` [:zeek:type:`AllAnalyzers::Tag`] of :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            [AllAnalyzers::ANALYZER_ANALYZER_SSH] = 1.0 hr,
            [AllAnalyzers::ANALYZER_ANALYZER_FTP] = 1.0 hr
         }


   Define inactivity timeouts by the service detected being used over
   the connection.

.. zeek:id:: Conn::port_inactivity_timeouts
   :source-code: base/protocols/conn/inactivity.zeek 15 15

   :Type: :zeek:type:`table` [:zeek:type:`port`] of :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            [513/tcp] = 1.0 hr,
            [21/tcp] = 1.0 hr,
            [23/tcp] = 1.0 hr,
            [22/tcp] = 1.0 hr
         }


   Define inactivity timeouts based on common protocol ports.


