:tocdepth: 3

base/bif/input.bif.zeek
=======================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Input

Internal functions and types used by the input framework.

:Namespaces: GLOBAL, Input

Summary
~~~~~~~
Functions
#########
================================================================= =
:zeek:id:`Input::__create_analysis_stream`: :zeek:type:`function` 
:zeek:id:`Input::__create_event_stream`: :zeek:type:`function`    
:zeek:id:`Input::__create_table_stream`: :zeek:type:`function`    
:zeek:id:`Input::__force_update`: :zeek:type:`function`           
:zeek:id:`Input::__remove_stream`: :zeek:type:`function`          
================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Input::__create_analysis_stream
   :source-code: base/bif/input.bif.zeek 28 28

   :Type: :zeek:type:`function` (description: :zeek:type:`Input::AnalysisDescription`) : :zeek:type:`bool`


.. zeek:id:: Input::__create_event_stream
   :source-code: base/bif/input.bif.zeek 25 25

   :Type: :zeek:type:`function` (description: :zeek:type:`Input::EventDescription`) : :zeek:type:`bool`


.. zeek:id:: Input::__create_table_stream
   :source-code: base/bif/input.bif.zeek 22 22

   :Type: :zeek:type:`function` (description: :zeek:type:`Input::TableDescription`) : :zeek:type:`bool`


.. zeek:id:: Input::__force_update
   :source-code: base/bif/input.bif.zeek 34 34

   :Type: :zeek:type:`function` (id: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Input::__remove_stream
   :source-code: base/bif/input.bif.zeek 31 31

   :Type: :zeek:type:`function` (id: :zeek:type:`string`) : :zeek:type:`bool`



