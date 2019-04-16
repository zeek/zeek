:tocdepth: 3

base/bif/plugins/Bro_FileEntropy.events.bif.zeek
================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================= ========================================================
:bro:id:`file_entropy`: :bro:type:`event` This event is generated each time file analysis performs
                                          entropy testing on a file.
========================================= ========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: file_entropy

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, ent: :bro:type:`entropy_test_result`)

   This event is generated each time file analysis performs
   entropy testing on a file.
   

   :f: The file.
   

   :ent: The results of the entropy testing.
   


