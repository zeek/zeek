:tocdepth: 3

base/bif/plugins/Bro_FileHash.events.bif.zeek
=============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
====================================== =========================================================================
:bro:id:`file_hash`: :bro:type:`event` This event is generated each time file analysis generates a digest of the
                                       file contents.
====================================== =========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: file_hash

   :Type: :bro:type:`event` (f: :bro:type:`fa_file`, kind: :bro:type:`string`, hash: :bro:type:`string`)

   This event is generated each time file analysis generates a digest of the
   file contents.
   

   :f: The file.
   

   :kind: The type of digest algorithm.
   

   :hash: The result of the hashing.
   
   .. bro:see:: Files::add_analyzer Files::ANALYZER_MD5
      Files::ANALYZER_SHA1 Files::ANALYZER_SHA256


