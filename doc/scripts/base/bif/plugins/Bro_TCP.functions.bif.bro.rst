:tocdepth: 3

base/bif/plugins/Bro_TCP.functions.bif.bro
==========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
================================================= ======================================================================
:bro:id:`get_contents_file`: :bro:type:`function` Returns the file handle of the contents file of a connection.
:bro:id:`get_orig_seq`: :bro:type:`function`      Get the originator sequence number of a TCP connection.
:bro:id:`get_resp_seq`: :bro:type:`function`      Get the responder sequence number of a TCP connection.
:bro:id:`set_contents_file`: :bro:type:`function` Associates a file handle with a connection for writing TCP byte stream
                                                  contents.
================================================= ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: get_contents_file

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`, direction: :bro:type:`count`) : :bro:type:`file`

   Returns the file handle of the contents file of a connection.
   

   :cid: The connection ID.
   

   :direction: Controls what sides of the connection to record. See
              :bro:id:`set_contents_file` for possible values.
   

   :returns: The :bro:type:`file` handle for the contents file of the
            connection identified by *cid*. If the connection exists
            but there is no contents file for *direction*, then the function
            generates an error and returns a file handle to ``stderr``.
   
   .. bro:see:: set_contents_file set_record_packets contents_file_write_failure

.. bro:id:: get_orig_seq

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`) : :bro:type:`count`

   Get the originator sequence number of a TCP connection. Sequence numbers
   are absolute (i.e., they reflect the values seen directly in packet headers;
   they are not relative to the beginning of the connection).
   

   :cid: The connection ID.
   

   :returns: The highest sequence number sent by a connection's originator, or 0
            if *cid* does not point to an active TCP connection.
   
   .. bro:see:: get_resp_seq

.. bro:id:: get_resp_seq

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`) : :bro:type:`count`

   Get the responder sequence number of a TCP connection. Sequence numbers
   are absolute (i.e., they reflect the values seen directly in packet headers;
   they are not relative to the beginning of the connection).
   

   :cid: The connection ID.
   

   :returns: The highest sequence number sent by a connection's responder, or 0
            if *cid* does not point to an active TCP connection.
   
   .. bro:see:: get_orig_seq

.. bro:id:: set_contents_file

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`, direction: :bro:type:`count`, f: :bro:type:`file`) : :bro:type:`bool`

   Associates a file handle with a connection for writing TCP byte stream
   contents.
   

   :cid: The connection ID.
   

   :direction: Controls what sides of the connection to record. The argument can
              take one of the four values:
   
              - ``CONTENTS_NONE``: Stop recording the connection's content.
              - ``CONTENTS_ORIG``: Record the data sent by the connection
                originator (often the client).
              - ``CONTENTS_RESP``: Record the data sent by the connection
                responder (often the server).
              - ``CONTENTS_BOTH``: Record the data sent in both directions.
                Results in the two directions being intermixed in the file,
                in the order the data was seen by Bro.
   

   :f: The file handle of the file to write the contents to.
   

   :returns: Returns false if *cid* does not point to an active connection, and
            true otherwise.
   
   .. note::
   
       The data recorded to the file reflects the byte stream, not the
       contents of individual packets. Reordering and duplicates are
       removed. If any data is missing, the recording stops at the
       missing data; this can happen, e.g., due to an
       :bro:id:`content_gap` event.
   
   .. bro:see:: get_contents_file set_record_packets contents_file_write_failure


