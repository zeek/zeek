:tocdepth: 3

base/utils/conn-ids.zeek
========================
.. bro:namespace:: GLOBAL

Simple functions for generating ASCII strings from connection IDs.

:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
================================================== ====================================================================
:bro:id:`directed_id_string`: :bro:type:`function` Calls :bro:id:`id_string` or :bro:id:`reverse_id_string` if the
                                                   second argument is T or F, respectively.
:bro:id:`id_string`: :bro:type:`function`          Takes a conn_id record and returns a string representation with the 
                                                   general data flow appearing to be from the connection originator
                                                   on the left to the responder on the right.
:bro:id:`reverse_id_string`: :bro:type:`function`  Takes a conn_id record and returns a string representation with the 
                                                   general data flow appearing to be from the connection responder
                                                   on the right to the originator on the left.
================================================== ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: directed_id_string

   :Type: :bro:type:`function` (id: :bro:type:`conn_id`, is_orig: :bro:type:`bool`) : :bro:type:`string`

   Calls :bro:id:`id_string` or :bro:id:`reverse_id_string` if the
   second argument is T or F, respectively.

.. bro:id:: id_string

   :Type: :bro:type:`function` (id: :bro:type:`conn_id`) : :bro:type:`string`

   Takes a conn_id record and returns a string representation with the 
   general data flow appearing to be from the connection originator
   on the left to the responder on the right.

.. bro:id:: reverse_id_string

   :Type: :bro:type:`function` (id: :bro:type:`conn_id`) : :bro:type:`string`

   Takes a conn_id record and returns a string representation with the 
   general data flow appearing to be from the connection responder
   on the right to the originator on the left.


