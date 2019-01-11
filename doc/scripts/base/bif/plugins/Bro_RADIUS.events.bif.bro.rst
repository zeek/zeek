:tocdepth: 3

base/bif/plugins/Bro_RADIUS.events.bif.bro
==========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================= ====================================
:bro:id:`radius_attribute`: :bro:type:`event` Generated for each RADIUS attribute.
:bro:id:`radius_message`: :bro:type:`event`   Generated for RADIUS messages.
============================================= ====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: radius_attribute

   :Type: :bro:type:`event` (c: :bro:type:`connection`, attr_type: :bro:type:`count`, value: :bro:type:`string`)

   Generated for each RADIUS attribute.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/RADIUS>`__ for more
   information about RADIUS.
   

   :c: The connection.
   

   :attr_type: The value of the code field (1 == User-Name, 2 == User-Password, etc.).
   

   :value: The data/value bound to the attribute.
   

.. bro:id:: radius_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, result: :bro:type:`RADIUS::Message`)

   Generated for RADIUS messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/RADIUS>`__ for more
   information about RADIUS.
   

   :c: The connection.
   

   :result: A record containing fields parsed from a RADIUS packet.
   


