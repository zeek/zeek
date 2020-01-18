:tocdepth: 3

base/frameworks/supervisor/main.zeek
====================================
.. zeek:namespace:: Supervisor

Implements Zeek process supervision configuration options and default
behavior.

:Namespace: Supervisor
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`base/frameworks/supervisor/api.zeek </scripts/base/frameworks/supervisor/api.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
============================================================================ =================================================================
:zeek:id:`Supervisor::topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef` The Broker topic prefix to use when subscribing to Supervisor API
                                                                             requests and when publishing Supervisor API responses.
============================================================================ =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Supervisor::topic_prefix

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/supervisor"``

   The Broker topic prefix to use when subscribing to Supervisor API
   requests and when publishing Supervisor API responses.  If you are
   publishing Supervisor requests, this is also the prefix string to use
   for their topic names.


