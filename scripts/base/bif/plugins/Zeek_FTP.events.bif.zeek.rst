:tocdepth: 3

base/bif/plugins/Zeek_FTP.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================== =======================================
:zeek:id:`ftp_reply`: :zeek:type:`event`   Generated for server-side FTP replies.
:zeek:id:`ftp_request`: :zeek:type:`event` Generated for client-side FTP commands.
========================================== =======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: ftp_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, code: :zeek:type:`count`, msg: :zeek:type:`string`, cont_resp: :zeek:type:`bool`)

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
   
   .. zeek:see:: ftp_request fmt_ftp_port parse_eftp_port
      parse_ftp_epsv parse_ftp_pasv parse_ftp_port

.. zeek:id:: ftp_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, command: :zeek:type:`string`, arg: :zeek:type:`string`)

   Generated for client-side FTP commands.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/File_Transfer_Protocol>`__ for
   more information about the FTP protocol.
   

   :c: The connection.
   

   :command: The FTP command issued by the client (without any arguments).
   

   :arg: The arguments going with the command.
   
   .. zeek:see:: ftp_reply fmt_ftp_port parse_eftp_port
      parse_ftp_epsv parse_ftp_pasv parse_ftp_port


