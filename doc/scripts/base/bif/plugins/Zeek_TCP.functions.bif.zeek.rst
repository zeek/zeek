:tocdepth: 3

base/bif/plugins/Zeek_TCP.functions.bif.zeek
============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
=================================================== ======================================================================
:zeek:id:`get_contents_file`: :zeek:type:`function` Returns the file handle of the contents file of a connection.
:zeek:id:`get_orig_seq`: :zeek:type:`function`      Get the originator sequence number of a TCP connection.
:zeek:id:`get_resp_seq`: :zeek:type:`function`      Get the responder sequence number of a TCP connection.
:zeek:id:`set_contents_file`: :zeek:type:`function` Associates a file handle with a connection for writing TCP byte stream
                                                    contents.
=================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: get_contents_file
   :source-code: base/bif/plugins/Zeek_TCP.functions.bif.zeek 80 80

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, direction: :zeek:type:`count`) : :zeek:type:`file`

   Returns the file handle of the contents file of a connection.
   

   :param cid: The connection ID.
   

   :param direction: Controls what sides of the connection to record. See
              :zeek:id:`set_contents_file` for possible values.
   

   :returns: The :zeek:type:`file` handle for the contents file of the
            connection identified by *cid*. If the connection exists
            but there is no contents file for *direction*, then the function
            generates an error and returns a file handle to ``stderr``.
   
   .. zeek:see:: set_contents_file set_record_packets contents_file_write_failure

.. zeek:id:: get_orig_seq
   :source-code: base/bif/plugins/Zeek_TCP.functions.bif.zeek 17 17

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`count`

   Get the originator sequence number of a TCP connection. Sequence numbers
   are absolute (i.e., they reflect the values seen directly in packet headers;
   they are not relative to the beginning of the connection).
   

   :param cid: The connection ID.
   

   :returns: The highest sequence number sent by a connection's originator, or 0
            if *cid* does not point to an active TCP connection.
   
   .. zeek:see:: get_resp_seq

.. zeek:id:: get_resp_seq
   :source-code: base/bif/plugins/Zeek_TCP.functions.bif.zeek 30 30

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`count`

   Get the responder sequence number of a TCP connection. Sequence numbers
   are absolute (i.e., they reflect the values seen directly in packet headers;
   they are not relative to the beginning of the connection).
   

   :param cid: The connection ID.
   

   :returns: The highest sequence number sent by a connection's responder, or 0
            if *cid* does not point to an active TCP connection.
   
   .. zeek:see:: get_orig_seq

.. zeek:id:: set_contents_file
   :source-code: base/bif/plugins/Zeek_TCP.functions.bif.zeek 64 64

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, direction: :zeek:type:`count`, f: :zeek:type:`file`) : :zeek:type:`bool`

   Associates a file handle with a connection for writing TCP byte stream
   contents.
   

   :param cid: The connection ID.
   

   :param direction: Controls what sides of the connection to record. The argument can
              take one of the four values:
   
              - ``CONTENTS_NONE``: Stop recording the connection's content.
              - ``CONTENTS_ORIG``: Record the data sent by the connection
                originator (often the client).
              - ``CONTENTS_RESP``: Record the data sent by the connection
                responder (often the server).
              - ``CONTENTS_BOTH``: Record the data sent in both directions.
                Results in the two directions being intermixed in the file,
                in the order the data was seen by Zeek.
   

   :param f: The file handle of the file to write the contents to.
   

   :returns: Returns false if *cid* does not point to an active connection, and
            true otherwise.
   
   .. note::
   
       The data recorded to the file reflects the byte stream, not the
       contents of individual packets. Reordering and duplicates are
       removed. If any data is missing, the recording stops at the
       missing data; this can happen, e.g., due to an
       :zeek:id:`content_gap` event.
   
   .. zeek:see:: get_contents_file set_record_packets contents_file_write_failure


