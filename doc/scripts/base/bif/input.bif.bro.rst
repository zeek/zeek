:tocdepth: 3

base/bif/input.bif.bro
======================
.. bro:namespace:: GLOBAL
.. bro:namespace:: Input

Internal functions and types used by the input framework.

:Namespaces: GLOBAL, Input

Summary
~~~~~~~
Functions
#########
=============================================================== =
:bro:id:`Input::__create_analysis_stream`: :bro:type:`function` 
:bro:id:`Input::__create_event_stream`: :bro:type:`function`    
:bro:id:`Input::__create_table_stream`: :bro:type:`function`    
:bro:id:`Input::__force_update`: :bro:type:`function`           
:bro:id:`Input::__remove_stream`: :bro:type:`function`          
=============================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: Input::__create_analysis_stream

   :Type: :bro:type:`function` (description: :bro:type:`Input::AnalysisDescription`) : :bro:type:`bool`


.. bro:id:: Input::__create_event_stream

   :Type: :bro:type:`function` (description: :bro:type:`Input::EventDescription`) : :bro:type:`bool`


.. bro:id:: Input::__create_table_stream

   :Type: :bro:type:`function` (description: :bro:type:`Input::TableDescription`) : :bro:type:`bool`


.. bro:id:: Input::__force_update

   :Type: :bro:type:`function` (id: :bro:type:`string`) : :bro:type:`bool`


.. bro:id:: Input::__remove_stream

   :Type: :bro:type:`function` (id: :bro:type:`string`) : :bro:type:`bool`



