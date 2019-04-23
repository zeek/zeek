:tocdepth: 3

base/bif/logging.bif.zeek
=========================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Log

Internal functions and types used by the logging framework.

:Namespaces: GLOBAL, Log

Summary
~~~~~~~
Functions
#########
======================================================= =
:zeek:id:`Log::__add_filter`: :zeek:type:`function`     
:zeek:id:`Log::__create_stream`: :zeek:type:`function`  
:zeek:id:`Log::__disable_stream`: :zeek:type:`function` 
:zeek:id:`Log::__enable_stream`: :zeek:type:`function`  
:zeek:id:`Log::__flush`: :zeek:type:`function`          
:zeek:id:`Log::__remove_filter`: :zeek:type:`function`  
:zeek:id:`Log::__remove_stream`: :zeek:type:`function`  
:zeek:id:`Log::__set_buf`: :zeek:type:`function`        
:zeek:id:`Log::__write`: :zeek:type:`function`          
======================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Log::__add_filter

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, filter: :zeek:type:`Log::Filter`) : :zeek:type:`bool`


.. zeek:id:: Log::__create_stream

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, stream: :zeek:type:`Log::Stream`) : :zeek:type:`bool`


.. zeek:id:: Log::__disable_stream

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`


.. zeek:id:: Log::__enable_stream

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`


.. zeek:id:: Log::__flush

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`


.. zeek:id:: Log::__remove_filter

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, name: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Log::__remove_stream

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`


.. zeek:id:: Log::__set_buf

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, buffered: :zeek:type:`bool`) : :zeek:type:`bool`


.. zeek:id:: Log::__write

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, columns: :zeek:type:`any`) : :zeek:type:`bool`



