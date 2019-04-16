:tocdepth: 3

base/bif/plugins/Bro_File.events.bif.zeek
=========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================= ========================================================================
:bro:id:`file_transferred`: :bro:type:`event` Generated when a TCP connection associated w/ file data transfer is seen
                                              (e.g.
============================================= ========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: file_transferred

   :Type: :bro:type:`event` (c: :bro:type:`connection`, prefix: :bro:type:`string`, descr: :bro:type:`string`, mime_type: :bro:type:`string`)

   Generated when a TCP connection associated w/ file data transfer is seen
   (e.g. as happens w/ FTP or IRC).
   

   :c: The connection over which file data is transferred.
   

   :prefix: Up to 1024 bytes of the file data.
   

   :descr: Deprecated/unused argument.
   

   :mime_type: MIME type of the file or "<unknown>" if no file magic signatures
              matched.


