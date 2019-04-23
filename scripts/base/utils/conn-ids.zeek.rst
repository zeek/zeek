:tocdepth: 3

base/utils/conn-ids.zeek
========================
.. zeek:namespace:: GLOBAL

Simple functions for generating ASCII strings from connection IDs.

:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
==================================================== ====================================================================
:zeek:id:`directed_id_string`: :zeek:type:`function` Calls :zeek:id:`id_string` or :zeek:id:`reverse_id_string` if the
                                                     second argument is T or F, respectively.
:zeek:id:`id_string`: :zeek:type:`function`          Takes a conn_id record and returns a string representation with the 
                                                     general data flow appearing to be from the connection originator
                                                     on the left to the responder on the right.
:zeek:id:`reverse_id_string`: :zeek:type:`function`  Takes a conn_id record and returns a string representation with the 
                                                     general data flow appearing to be from the connection responder
                                                     on the right to the originator on the left.
==================================================== ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: directed_id_string

   :Type: :zeek:type:`function` (id: :zeek:type:`conn_id`, is_orig: :zeek:type:`bool`) : :zeek:type:`string`

   Calls :zeek:id:`id_string` or :zeek:id:`reverse_id_string` if the
   second argument is T or F, respectively.

.. zeek:id:: id_string

   :Type: :zeek:type:`function` (id: :zeek:type:`conn_id`) : :zeek:type:`string`

   Takes a conn_id record and returns a string representation with the 
   general data flow appearing to be from the connection originator
   on the left to the responder on the right.

.. zeek:id:: reverse_id_string

   :Type: :zeek:type:`function` (id: :zeek:type:`conn_id`) : :zeek:type:`string`

   Takes a conn_id record and returns a string representation with the 
   general data flow appearing to be from the connection responder
   on the right to the originator on the left.


