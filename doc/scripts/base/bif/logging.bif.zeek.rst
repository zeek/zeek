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
================================================================= =
:zeek:id:`Log::__add_filter`: :zeek:type:`function`               
:zeek:id:`Log::__create_stream`: :zeek:type:`function`            
:zeek:id:`Log::__delay`: :zeek:type:`function`                    
:zeek:id:`Log::__delay_finish`: :zeek:type:`function`             
:zeek:id:`Log::__disable_stream`: :zeek:type:`function`           
:zeek:id:`Log::__enable_stream`: :zeek:type:`function`            
:zeek:id:`Log::__flush`: :zeek:type:`function`                    
:zeek:id:`Log::__get_delay_queue_size`: :zeek:type:`function`     
:zeek:id:`Log::__remove_filter`: :zeek:type:`function`            
:zeek:id:`Log::__remove_stream`: :zeek:type:`function`            
:zeek:id:`Log::__set_buf`: :zeek:type:`function`                  
:zeek:id:`Log::__set_max_delay_interval`: :zeek:type:`function`   
:zeek:id:`Log::__set_max_delay_queue_size`: :zeek:type:`function` 
:zeek:id:`Log::__write`: :zeek:type:`function`                    
:zeek:id:`Log::flush_all`: :zeek:type:`function`                  
================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Log::__add_filter
   :source-code: base/bif/logging.bif.zeek 35 35

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, filter: :zeek:type:`Log::Filter`) : :zeek:type:`bool`


.. zeek:id:: Log::__create_stream
   :source-code: base/bif/logging.bif.zeek 23 23

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, stream: :zeek:type:`Log::Stream`) : :zeek:type:`bool`


.. zeek:id:: Log::__delay
   :source-code: base/bif/logging.bif.zeek 55 55

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, rec: :zeek:type:`any`, post_delay_cb: :zeek:type:`Log::PostDelayCallback`) : :zeek:type:`Log::DelayToken`


.. zeek:id:: Log::__delay_finish
   :source-code: base/bif/logging.bif.zeek 58 58

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, rec: :zeek:type:`any`, token: :zeek:type:`Log::DelayToken`) : :zeek:type:`bool`


.. zeek:id:: Log::__disable_stream
   :source-code: base/bif/logging.bif.zeek 32 32

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`


.. zeek:id:: Log::__enable_stream
   :source-code: base/bif/logging.bif.zeek 29 29

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`


.. zeek:id:: Log::__flush
   :source-code: base/bif/logging.bif.zeek 47 47

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`


.. zeek:id:: Log::__get_delay_queue_size
   :source-code: base/bif/logging.bif.zeek 67 67

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`int`


.. zeek:id:: Log::__remove_filter
   :source-code: base/bif/logging.bif.zeek 38 38

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, name: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Log::__remove_stream
   :source-code: base/bif/logging.bif.zeek 26 26

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`


.. zeek:id:: Log::__set_buf
   :source-code: base/bif/logging.bif.zeek 44 44

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, buffered: :zeek:type:`bool`) : :zeek:type:`bool`


.. zeek:id:: Log::__set_max_delay_interval
   :source-code: base/bif/logging.bif.zeek 61 61

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, max_delay: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Log::__set_max_delay_queue_size
   :source-code: base/bif/logging.bif.zeek 64 64

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, max_queue_size: :zeek:type:`count`) : :zeek:type:`bool`


.. zeek:id:: Log::__write
   :source-code: base/bif/logging.bif.zeek 41 41

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, columns: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Log::flush_all
   :source-code: base/bif/logging.bif.zeek 52 52

   :Type: :zeek:type:`function` () : :zeek:type:`any`



