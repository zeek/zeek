:tocdepth: 3

base/bif/analyzer.bif.bro
=========================
.. bro:namespace:: Analyzer
.. bro:namespace:: GLOBAL

Internal functions and types used by the analyzer framework.

:Namespaces: Analyzer, GLOBAL

Summary
~~~~~~~
Functions
#########
================================================================= =
:bro:id:`Analyzer::__disable_all_analyzers`: :bro:type:`function` 
:bro:id:`Analyzer::__disable_analyzer`: :bro:type:`function`      
:bro:id:`Analyzer::__enable_analyzer`: :bro:type:`function`       
:bro:id:`Analyzer::__name`: :bro:type:`function`                  
:bro:id:`Analyzer::__register_for_port`: :bro:type:`function`     
:bro:id:`Analyzer::__schedule_analyzer`: :bro:type:`function`     
:bro:id:`Analyzer::__tag`: :bro:type:`function`                   
================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: Analyzer::__disable_all_analyzers

   :Type: :bro:type:`function` () : :bro:type:`any`


.. bro:id:: Analyzer::__disable_analyzer

   :Type: :bro:type:`function` (id: :bro:type:`Analyzer::Tag`) : :bro:type:`bool`


.. bro:id:: Analyzer::__enable_analyzer

   :Type: :bro:type:`function` (id: :bro:type:`Analyzer::Tag`) : :bro:type:`bool`


.. bro:id:: Analyzer::__name

   :Type: :bro:type:`function` (atype: :bro:type:`Analyzer::Tag`) : :bro:type:`string`


.. bro:id:: Analyzer::__register_for_port

   :Type: :bro:type:`function` (id: :bro:type:`Analyzer::Tag`, p: :bro:type:`port`) : :bro:type:`bool`


.. bro:id:: Analyzer::__schedule_analyzer

   :Type: :bro:type:`function` (orig: :bro:type:`addr`, resp: :bro:type:`addr`, resp_p: :bro:type:`port`, analyzer: :bro:type:`Analyzer::Tag`, tout: :bro:type:`interval`) : :bro:type:`bool`


.. bro:id:: Analyzer::__tag

   :Type: :bro:type:`function` (name: :bro:type:`string`) : :bro:type:`Analyzer::Tag`



