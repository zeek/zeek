:tocdepth: 3

base/bif/plugins/Bro_FTP.events.bif.zeek
========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================== =======================================
:bro:id:`ftp_reply`: :bro:type:`event`   Generated for server-side FTP replies.
:bro:id:`ftp_request`: :bro:type:`event` Generated for client-side FTP commands.
======================================== =======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: ftp_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, code: :bro:type:`count`, msg: :bro:type:`string`, cont_resp: :bro:type:`bool`)

   Generated for server-side FTP replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/File_Transfer_Protocol>`__ for
   more information about the FTP protocol.
   

   :c: The connection.
   

   :code: The numerical response code the server responded with.
   

   :msg:  The textual message of the response.
   

   :cont_resp: True if the reply line is tagged as being continued to the next
              line. If so, further events will be raised and a handler may want
              to reassemble the pieces before processing the response any
              further.
   
   .. bro:see:: ftp_request fmt_ftp_port parse_eftp_port
      parse_ftp_epsv parse_ftp_pasv parse_ftp_port

.. bro:id:: ftp_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, command: :bro:type:`string`, arg: :bro:type:`string`)

   Generated for client-side FTP commands.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/File_Transfer_Protocol>`__ for
   more information about the FTP protocol.
   

   :c: The connection.
   

   :command: The FTP command issued by the client (without any arguments).
   

   :arg: The arguments going with the command.
   
   .. bro:see:: ftp_reply fmt_ftp_port parse_eftp_port
      parse_ftp_epsv parse_ftp_pasv parse_ftp_port


