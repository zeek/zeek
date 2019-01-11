:tocdepth: 3

base/bif/logging.bif.bro
========================
.. bro:namespace:: GLOBAL
.. bro:namespace:: Log

Internal functions and types used by the logging framework.

:Namespaces: GLOBAL, Log

Summary
~~~~~~~
Functions
#########
===================================================== =
:bro:id:`Log::__add_filter`: :bro:type:`function`     
:bro:id:`Log::__create_stream`: :bro:type:`function`  
:bro:id:`Log::__disable_stream`: :bro:type:`function` 
:bro:id:`Log::__enable_stream`: :bro:type:`function`  
:bro:id:`Log::__flush`: :bro:type:`function`          
:bro:id:`Log::__remove_filter`: :bro:type:`function`  
:bro:id:`Log::__remove_stream`: :bro:type:`function`  
:bro:id:`Log::__set_buf`: :bro:type:`function`        
:bro:id:`Log::__write`: :bro:type:`function`          
===================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: Log::__add_filter

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`, filter: :bro:type:`Log::Filter`) : :bro:type:`bool`


.. bro:id:: Log::__create_stream

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`, stream: :bro:type:`Log::Stream`) : :bro:type:`bool`


.. bro:id:: Log::__disable_stream

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`) : :bro:type:`bool`


.. bro:id:: Log::__enable_stream

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`) : :bro:type:`bool`


.. bro:id:: Log::__flush

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`) : :bro:type:`bool`


.. bro:id:: Log::__remove_filter

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`, name: :bro:type:`string`) : :bro:type:`bool`


.. bro:id:: Log::__remove_stream

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`) : :bro:type:`bool`


.. bro:id:: Log::__set_buf

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`, buffered: :bro:type:`bool`) : :bro:type:`bool`


.. bro:id:: Log::__write

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`, columns: :bro:type:`any`) : :bro:type:`bool`



