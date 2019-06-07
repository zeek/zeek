:tocdepth: 3

base/bif/plugins/Bro_RPC.events.bif.zeek
========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================= ==========================================================================
:zeek:id:`mount_proc_mnt`: :zeek:type:`event`             Generated for MOUNT3 request/reply dialogues of type *mnt*.
:zeek:id:`mount_proc_not_implemented`: :zeek:type:`event` Generated for MOUNT3 request/reply dialogues of a type that Zeek's MOUNTv3
                                                          analyzer does not implement.
:zeek:id:`mount_proc_null`: :zeek:type:`event`            Generated for MOUNT3 request/reply dialogues of type *null*.
:zeek:id:`mount_proc_umnt`: :zeek:type:`event`            Generated for MOUNT3 request/reply dialogues of type *umnt*.
:zeek:id:`mount_proc_umnt_all`: :zeek:type:`event`        Generated for MOUNT3 request/reply dialogues of type *umnt_all*.
:zeek:id:`mount_reply_status`: :zeek:type:`event`         Generated for each MOUNT3 reply message received, reporting just the
                                                          status included.
:zeek:id:`nfs_proc_create`: :zeek:type:`event`            Generated for NFSv3 request/reply dialogues of type *create*.
:zeek:id:`nfs_proc_getattr`: :zeek:type:`event`           Generated for NFSv3 request/reply dialogues of type *getattr*.
:zeek:id:`nfs_proc_link`: :zeek:type:`event`              Generated for NFSv3 request/reply dialogues of type *link*.
:zeek:id:`nfs_proc_lookup`: :zeek:type:`event`            Generated for NFSv3 request/reply dialogues of type *lookup*.
:zeek:id:`nfs_proc_mkdir`: :zeek:type:`event`             Generated for NFSv3 request/reply dialogues of type *mkdir*.
:zeek:id:`nfs_proc_not_implemented`: :zeek:type:`event`   Generated for NFSv3 request/reply dialogues of a type that Zeek's NFSv3
                                                          analyzer does not implement.
:zeek:id:`nfs_proc_null`: :zeek:type:`event`              Generated for NFSv3 request/reply dialogues of type *null*.
:zeek:id:`nfs_proc_read`: :zeek:type:`event`              Generated for NFSv3 request/reply dialogues of type *read*.
:zeek:id:`nfs_proc_readdir`: :zeek:type:`event`           Generated for NFSv3 request/reply dialogues of type *readdir*.
:zeek:id:`nfs_proc_readlink`: :zeek:type:`event`          Generated for NFSv3 request/reply dialogues of type *readlink*.
:zeek:id:`nfs_proc_remove`: :zeek:type:`event`            Generated for NFSv3 request/reply dialogues of type *remove*.
:zeek:id:`nfs_proc_rename`: :zeek:type:`event`            Generated for NFSv3 request/reply dialogues of type *rename*.
:zeek:id:`nfs_proc_rmdir`: :zeek:type:`event`             Generated for NFSv3 request/reply dialogues of type *rmdir*.
:zeek:id:`nfs_proc_sattr`: :zeek:type:`event`             Generated for NFSv3 request/reply dialogues of type *sattr*.
:zeek:id:`nfs_proc_symlink`: :zeek:type:`event`           Generated for NFSv3 request/reply dialogues of type *symlink*.
:zeek:id:`nfs_proc_write`: :zeek:type:`event`             Generated for NFSv3 request/reply dialogues of type *write*.
:zeek:id:`nfs_reply_status`: :zeek:type:`event`           Generated for each NFSv3 reply message received, reporting just the
                                                          status included.
:zeek:id:`pm_attempt_callit`: :zeek:type:`event`          Generated for failed Portmapper requests of type *callit*.
:zeek:id:`pm_attempt_dump`: :zeek:type:`event`            Generated for failed Portmapper requests of type *dump*.
:zeek:id:`pm_attempt_getport`: :zeek:type:`event`         Generated for failed Portmapper requests of type *getport*.
:zeek:id:`pm_attempt_null`: :zeek:type:`event`            Generated for failed Portmapper requests of type *null*.
:zeek:id:`pm_attempt_set`: :zeek:type:`event`             Generated for failed Portmapper requests of type *set*.
:zeek:id:`pm_attempt_unset`: :zeek:type:`event`           Generated for failed Portmapper requests of type *unset*.
:zeek:id:`pm_bad_port`: :zeek:type:`event`                Generated for Portmapper requests or replies that include an invalid port
                                                          number.
:zeek:id:`pm_request_callit`: :zeek:type:`event`          Generated for Portmapper request/reply dialogues of type *callit*.
:zeek:id:`pm_request_dump`: :zeek:type:`event`            Generated for Portmapper request/reply dialogues of type *dump*.
:zeek:id:`pm_request_getport`: :zeek:type:`event`         Generated for Portmapper request/reply dialogues of type *getport*.
:zeek:id:`pm_request_null`: :zeek:type:`event`            Generated for Portmapper requests of type *null*.
:zeek:id:`pm_request_set`: :zeek:type:`event`             Generated for Portmapper request/reply dialogues of type *set*.
:zeek:id:`pm_request_unset`: :zeek:type:`event`           Generated for Portmapper request/reply dialogues of type *unset*.
:zeek:id:`rpc_call`: :zeek:type:`event`                   Generated for RPC *call* messages.
:zeek:id:`rpc_dialogue`: :zeek:type:`event`               Generated for RPC request/reply *pairs*.
:zeek:id:`rpc_reply`: :zeek:type:`event`                  Generated for RPC *reply* messages.
========================================================= ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: mount_proc_mnt

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`MOUNT3::info_t`, req: :zeek:type:`MOUNT3::dirmntargs_t`, rep: :zeek:type:`MOUNT3::mnt_reply_t`)

   Generated for MOUNT3 request/reply dialogues of type *mnt*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: mount_proc_not_implemented

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`MOUNT3::info_t`, proc: :zeek:type:`MOUNT3::proc_t`)

   Generated for MOUNT3 request/reply dialogues of a type that Zeek's MOUNTv3
   analyzer does not implement.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :proc: The procedure called that Zeek does not implement.
   
   .. zeek:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: mount_proc_null

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`MOUNT3::info_t`)

   Generated for MOUNT3 request/reply dialogues of type *null*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   
   .. zeek:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: mount_proc_umnt

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`MOUNT3::info_t`, req: :zeek:type:`MOUNT3::dirmntargs_t`)

   Generated for MOUNT3 request/reply dialogues of type *umnt*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   
   .. zeek:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: mount_proc_umnt_all

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`MOUNT3::info_t`, req: :zeek:type:`MOUNT3::dirmntargs_t`)

   Generated for MOUNT3 request/reply dialogues of type *umnt_all*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   
   .. zeek:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: mount_reply_status

   :Type: :zeek:type:`event` (n: :zeek:type:`connection`, info: :zeek:type:`MOUNT3::info_t`)

   Generated for each MOUNT3 reply message received, reporting just the
   status included.
   

   :n: The connection.
   

   :info: Reports the status included in the reply.
   
   .. zeek:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_create

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::diropargs_t`, rep: :zeek:type:`NFS3::newobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *create*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req: TODO.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see::  nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_getattr

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, fh: :zeek:type:`string`, attrs: :zeek:type:`NFS3::fattr_t`)

   Generated for NFSv3 request/reply dialogues of type *getattr*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :fh: TODO.
   

   :attrs: The attributes returned in the reply. The values may not be valid if
         the request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create  nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply file_mode
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_link

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::linkargs_t`, rep: :zeek:type:`NFS3::link_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *link*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      nfs_proc_symlink rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_lookup

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::diropargs_t`, rep: :zeek:type:`NFS3::lookup_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *lookup*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr  nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_mkdir

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::diropargs_t`, rep: :zeek:type:`NFS3::newobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *mkdir*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req: TODO.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_not_implemented

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, proc: :zeek:type:`NFS3::proc_t`)

   Generated for NFSv3 request/reply dialogues of a type that Zeek's NFSv3
   analyzer does not implement.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :proc: The procedure called that Zeek does not implement.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_null nfs_proc_read nfs_proc_readdir nfs_proc_readlink nfs_proc_remove
      nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_null

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`)

   Generated for NFSv3 request/reply dialogues of type *null*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented  nfs_proc_read nfs_proc_readdir nfs_proc_readlink
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_read

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::readargs_t`, rep: :zeek:type:`NFS3::read_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *read*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_remove nfs_proc_rmdir
      nfs_proc_write nfs_reply_status rpc_call rpc_dialogue rpc_reply
      NFS3::return_data NFS3::return_data_first_only NFS3::return_data_max
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_readdir

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::readdirargs_t`, rep: :zeek:type:`NFS3::readdir_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *readdir*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req: TODO.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readlink
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_readlink

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, fh: :zeek:type:`string`, rep: :zeek:type:`NFS3::readlink_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *readlink*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :fh: The file handle passed in the request.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      nfs_proc_symlink rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_remove

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::diropargs_t`, rep: :zeek:type:`NFS3::delobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *remove*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req: TODO.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink  nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_rename

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::renameopargs_t`, rep: :zeek:type:`NFS3::renameobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *rename*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req: TODO.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rename nfs_proc_write
      nfs_reply_status rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_rmdir

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::diropargs_t`, rep: :zeek:type:`NFS3::delobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *rmdir*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req: TODO.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove  nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_sattr

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::sattrargs_t`, rep: :zeek:type:`NFS3::sattr_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *sattr*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   

   :rep: The attributes returned in the reply. The values may not be
        valid if the request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create  nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply file_mode
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_symlink

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::symlinkargs_t`, rep: :zeek:type:`NFS3::newobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *symlink*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   

   :rep: The attributes returned in the reply. The values may not be
        valid if the request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create  nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      nfs_proc_link rpc_call rpc_dialogue rpc_reply file_mode
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_write

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::writeargs_t`, rep: :zeek:type:`NFS3::write_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *write*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req: TODO.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir  nfs_reply_status rpc_call
      rpc_dialogue rpc_reply NFS3::return_data NFS3::return_data_first_only
      NFS3::return_data_max
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_reply_status

   :Type: :zeek:type:`event` (n: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`)

   Generated for each NFSv3 reply message received, reporting just the
   status included.
   

   :n: The connection.
   

   :info: Reports the status included in the reply.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_attempt_callit

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, status: :zeek:type:`rpc_status`, call: :zeek:type:`pm_callit_request`)

   Generated for failed Portmapper requests of type *callit*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   

   :call: The argument to the original request.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset
      pm_attempt_getport pm_attempt_dump pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_attempt_dump

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, status: :zeek:type:`rpc_status`)

   Generated for failed Portmapper requests of type *dump*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset
      pm_attempt_getport pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_attempt_getport

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, status: :zeek:type:`rpc_status`, pr: :zeek:type:`pm_port_request`)

   Generated for failed Portmapper requests of type *getport*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   

   :pr: The argument to the original request.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_attempt_null

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, status: :zeek:type:`rpc_status`)

   Generated for failed Portmapper requests of type *null*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_set pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_attempt_set

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, status: :zeek:type:`rpc_status`, m: :zeek:type:`pm_mapping`)

   Generated for failed Portmapper requests of type *set*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   

   :m: The argument to the original request.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_attempt_unset

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, status: :zeek:type:`rpc_status`, m: :zeek:type:`pm_mapping`)

   Generated for failed Portmapper requests of type *unset*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   

   :m: The argument to the original request.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_bad_port

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, bad_p: :zeek:type:`count`)

   Generated for Portmapper requests or replies that include an invalid port
   number. Since ports are represented by unsigned 4-byte integers, they can
   stray outside the allowed range of 0--65535 by being >= 65536. If so, this
   event is generated.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :bad_p: The invalid port value.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset
      pm_attempt_getport pm_attempt_dump pm_attempt_callit rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_request_callit

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, call: :zeek:type:`pm_callit_request`, p: :zeek:type:`port`)

   Generated for Portmapper request/reply dialogues of type *callit*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :call: The argument to the request.
   

   :p: The port value returned by the call.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_attempt_null
      pm_attempt_set pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_request_dump

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, m: :zeek:type:`pm_mappings`)

   Generated for Portmapper request/reply dialogues of type *dump*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :m: The mappings returned by the server.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_callit pm_attempt_null
      pm_attempt_set pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_request_getport

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, pr: :zeek:type:`pm_port_request`, p: :zeek:type:`port`)

   Generated for Portmapper request/reply dialogues of type *getport*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :pr: The argument to the request.
   

   :p: The port returned by the server.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_request_null

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`)

   Generated for Portmapper requests of type *null*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   
   .. zeek:see:: pm_request_set pm_request_unset pm_request_getport
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_request_set

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, m: :zeek:type:`pm_mapping`, success: :zeek:type:`bool`)

   Generated for Portmapper request/reply dialogues of type *set*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :m: The argument to the request.
   

   :success: True if the request was successful, according to the corresponding
            reply. If no reply was seen, this will be false once the request
            times out.
   
   .. zeek:see:: pm_request_null pm_request_unset pm_request_getport
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_request_unset

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, m: :zeek:type:`pm_mapping`, success: :zeek:type:`bool`)

   Generated for Portmapper request/reply dialogues of type *unset*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :m: The argument to the request.
   

   :success: True if the request was successful, according to the corresponding
            reply. If no reply was seen, this will be false once the request
            times out.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_getport
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: rpc_call

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, xid: :zeek:type:`count`, prog: :zeek:type:`count`, ver: :zeek:type:`count`, proc: :zeek:type:`count`, call_len: :zeek:type:`count`)

   Generated for RPC *call* messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ONC_RPC>`__ for more information
   about the ONC RPC protocol.
   

   :c: The connection.
   

   :xid: The transaction identifier allowing to match requests with replies.
   

   :prog: The remote program to call.
   

   :ver: The version of the remote program to call.
   

   :proc: The procedure of the remote program to call.
   

   :call_len: The size of the *call_body* PDU.
   
   .. zeek:see::  rpc_dialogue rpc_reply dce_rpc_bind dce_rpc_message dce_rpc_request
      dce_rpc_response rpc_timeout
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: rpc_dialogue

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, prog: :zeek:type:`count`, ver: :zeek:type:`count`, proc: :zeek:type:`count`, status: :zeek:type:`rpc_status`, start_time: :zeek:type:`time`, call_len: :zeek:type:`count`, reply_len: :zeek:type:`count`)

   Generated for RPC request/reply *pairs*. The RPC analyzer associates request
   and reply by their transaction identifiers and raises this event once both
   have been seen. If there's not a reply, this event will still be generated
   eventually on timeout. In that case, *status* will be set to
   :zeek:enum:`RPC_TIMEOUT`.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ONC_RPC>`__ for more information
   about the ONC RPC protocol.
   

   :c: The connection.
   

   :prog: The remote program to call.
   

   :ver: The version of the remote program to call.
   

   :proc: The procedure of the remote program to call.
   

   :status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   

   :start_time: The time when the *call* was seen.
   

   :call_len: The size of the *call_body* PDU.
   

   :reply_len: The size of the *reply_body* PDU.
   
   .. zeek:see:: rpc_call rpc_reply dce_rpc_bind dce_rpc_message dce_rpc_request
      dce_rpc_response rpc_timeout
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: rpc_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, xid: :zeek:type:`count`, status: :zeek:type:`rpc_status`, reply_len: :zeek:type:`count`)

   Generated for RPC *reply* messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ONC_RPC>`__ for more information
   about the ONC RPC protocol.
   

   :c: The connection.
   

   :xid: The transaction identifier allowing to match requests with replies.
   

   :status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   

   :reply_len: The size of the *reply_body* PDU.
   
   .. zeek:see:: rpc_call rpc_dialogue  dce_rpc_bind dce_rpc_message dce_rpc_request
      dce_rpc_response rpc_timeout
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.


