:tocdepth: 3

base/bif/plugins/Zeek_FileEntropy.events.bif.zeek
=================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=========================================== ========================================================
:zeek:id:`file_entropy`: :zeek:type:`event` This event is generated each time file analysis performs
                                            entropy testing on a file.
=========================================== ========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: file_entropy
   :source-code: policy/frameworks/files/entropy-test-all-files.zeek 16 19

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, ent: :zeek:type:`entropy_test_result`)

   This event is generated each time file analysis performs
   entropy testing on a file.
   

   :param f: The file.
   

   :param ent: The results of the entropy testing.
   


