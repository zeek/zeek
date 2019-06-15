:tocdepth: 3

base/bif/plugins/Zeek_RADIUS.events.bif.zeek
============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=============================================== ====================================
:zeek:id:`radius_attribute`: :zeek:type:`event` Generated for each RADIUS attribute.
:zeek:id:`radius_message`: :zeek:type:`event`   Generated for RADIUS messages.
=============================================== ====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: radius_attribute

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, attr_type: :zeek:type:`count`, value: :zeek:type:`string`)

   Generated for each RADIUS attribute.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/RADIUS>`__ for more
   information about RADIUS.
   

   :c: The connection.
   

   :attr_type: The value of the code field (1 == User-Name, 2 == User-Password, etc.).
   

   :value: The data/value bound to the attribute.
   

.. zeek:id:: radius_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, result: :zeek:type:`RADIUS::Message`)

   Generated for RADIUS messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/RADIUS>`__ for more
   information about RADIUS.
   

   :c: The connection.
   

   :result: A record containing fields parsed from a RADIUS packet.
   


