:tocdepth: 3

base/protocols/conn/inactivity.bro
==================================
.. bro:namespace:: Conn

Adjust the inactivity timeouts for interactive services which could
very possibly have long delays between packets.

:Namespace: Conn

Summary
~~~~~~~
Runtime Options
###############
================================================================================== ==================================================================
:bro:id:`Conn::analyzer_inactivity_timeouts`: :bro:type:`table` :bro:attr:`&redef` Define inactivity timeouts by the service detected being used over
                                                                                   the connection.
:bro:id:`Conn::port_inactivity_timeouts`: :bro:type:`table` :bro:attr:`&redef`     Define inactivity timeouts based on common protocol ports.
================================================================================== ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Conn::analyzer_inactivity_timeouts

   :Type: :bro:type:`table` [:bro:type:`Analyzer::Tag`] of :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         [Analyzer::ANALYZER_FTP] = 1.0 hr,
         [Analyzer::ANALYZER_SSH] = 1.0 hr
      }

   Define inactivity timeouts by the service detected being used over
   the connection.

.. bro:id:: Conn::port_inactivity_timeouts

   :Type: :bro:type:`table` [:bro:type:`port`] of :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         [22/tcp] = 1.0 hr,
         [513/tcp] = 1.0 hr,
         [21/tcp] = 1.0 hr,
         [23/tcp] = 1.0 hr
      }

   Define inactivity timeouts based on common protocol ports.


