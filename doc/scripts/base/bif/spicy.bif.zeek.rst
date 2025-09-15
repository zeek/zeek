:tocdepth: 3

base/bif/spicy.bif.zeek
=======================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Spicy


:Namespaces: GLOBAL, Spicy

Summary
~~~~~~~
Events
######
============================================================= =
:zeek:id:`Spicy::max_file_depth_exceeded`: :zeek:type:`event` 
============================================================= =

Functions
#########
========================================================== =
:zeek:id:`Spicy::__resource_usage`: :zeek:type:`function`  
:zeek:id:`Spicy::__toggle_analyzer`: :zeek:type:`function` 
========================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: Spicy::max_file_depth_exceeded
   :source-code: base/frameworks/spicy/main.zeek 9 15

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, args: :zeek:type:`Files::AnalyzerArgs`, limit: :zeek:type:`count`)


Functions
#########
.. zeek:id:: Spicy::__resource_usage
   :source-code: base/bif/spicy.bif.zeek 37 37

   :Type: :zeek:type:`function` () : :zeek:type:`Spicy::ResourceUsage`


.. zeek:id:: Spicy::__toggle_analyzer
   :source-code: base/bif/spicy.bif.zeek 32 32

   :Type: :zeek:type:`function` (tag: :zeek:type:`any`, enable: :zeek:type:`bool`) : :zeek:type:`bool`



