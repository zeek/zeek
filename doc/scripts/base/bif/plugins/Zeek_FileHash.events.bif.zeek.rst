:tocdepth: 3

base/bif/plugins/Zeek_FileHash.events.bif.zeek
==============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================== =========================================================================
:zeek:id:`file_hash`: :zeek:type:`event` This event is generated each time file analysis generates a digest of the
                                         file contents.
======================================== =========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: file_hash
   :source-code: base/bif/plugins/Zeek_FileHash.events.bif.zeek 15 15

   :Type: :zeek:type:`event` (f: :zeek:type:`fa_file`, kind: :zeek:type:`string`, hash: :zeek:type:`string`)

   This event is generated each time file analysis generates a digest of the
   file contents.
   

   :param f: The file.
   

   :param kind: The type of digest algorithm.
   

   :param hash: The result of the hashing.
   
   .. zeek:see:: Files::add_analyzer Files::ANALYZER_MD5
      Files::ANALYZER_SHA1 Files::ANALYZER_SHA256


