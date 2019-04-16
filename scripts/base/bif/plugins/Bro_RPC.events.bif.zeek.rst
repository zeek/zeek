:tocdepth: 3

base/bif/plugins/Bro_RPC.events.bif.zeek
========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================= =========================================================================
:bro:id:`mount_proc_mnt`: :bro:type:`event`             Generated for MOUNT3 request/reply dialogues of type *mnt*.
:bro:id:`mount_proc_not_implemented`: :bro:type:`event` Generated for MOUNT3 request/reply dialogues of a type that Bro's MOUNTv3
                                                        analyzer does not implement.
:bro:id:`mount_proc_null`: :bro:type:`event`            Generated for MOUNT3 request/reply dialogues of type *null*.
:bro:id:`mount_proc_umnt`: :bro:type:`event`            Generated for MOUNT3 request/reply dialogues of type *umnt*.
:bro:id:`mount_proc_umnt_all`: :bro:type:`event`        Generated for MOUNT3 request/reply dialogues of type *umnt_all*.
:bro:id:`mount_reply_status`: :bro:type:`event`         Generated for each MOUNT3 reply message received, reporting just the
                                                        status included.
:bro:id:`nfs_proc_create`: :bro:type:`event`            Generated for NFSv3 request/reply dialogues of type *create*.
:bro:id:`nfs_proc_getattr`: :bro:type:`event`           Generated for NFSv3 request/reply dialogues of type *getattr*.
:bro:id:`nfs_proc_link`: :bro:type:`event`              Generated for NFSv3 request/reply dialogues of type *link*.
:bro:id:`nfs_proc_lookup`: :bro:type:`event`            Generated for NFSv3 request/reply dialogues of type *lookup*.
:bro:id:`nfs_proc_mkdir`: :bro:type:`event`             Generated for NFSv3 request/reply dialogues of type *mkdir*.
:bro:id:`nfs_proc_not_implemented`: :bro:type:`event`   Generated for NFSv3 request/reply dialogues of a type that Bro's NFSv3
                                                        analyzer does not implement.
:bro:id:`nfs_proc_null`: :bro:type:`event`              Generated for NFSv3 request/reply dialogues of type *null*.
:bro:id:`nfs_proc_read`: :bro:type:`event`              Generated for NFSv3 request/reply dialogues of type *read*.
:bro:id:`nfs_proc_readdir`: :bro:type:`event`           Generated for NFSv3 request/reply dialogues of type *readdir*.
:bro:id:`nfs_proc_readlink`: :bro:type:`event`          Generated for NFSv3 request/reply dialogues of type *readlink*.
:bro:id:`nfs_proc_remove`: :bro:type:`event`            Generated for NFSv3 request/reply dialogues of type *remove*.
:bro:id:`nfs_proc_rename`: :bro:type:`event`            Generated for NFSv3 request/reply dialogues of type *rename*.
:bro:id:`nfs_proc_rmdir`: :bro:type:`event`             Generated for NFSv3 request/reply dialogues of type *rmdir*.
:bro:id:`nfs_proc_sattr`: :bro:type:`event`             Generated for NFSv3 request/reply dialogues of type *sattr*.
:bro:id:`nfs_proc_symlink`: :bro:type:`event`           Generated for NFSv3 request/reply dialogues of type *symlink*.
:bro:id:`nfs_proc_write`: :bro:type:`event`             Generated for NFSv3 request/reply dialogues of type *write*.
:bro:id:`nfs_reply_status`: :bro:type:`event`           Generated for each NFSv3 reply message received, reporting just the
                                                        status included.
:bro:id:`pm_attempt_callit`: :bro:type:`event`          Generated for failed Portmapper requests of type *callit*.
:bro:id:`pm_attempt_dump`: :bro:type:`event`            Generated for failed Portmapper requests of type *dump*.
:bro:id:`pm_attempt_getport`: :bro:type:`event`         Generated for failed Portmapper requests of type *getport*.
:bro:id:`pm_attempt_null`: :bro:type:`event`            Generated for failed Portmapper requests of type *null*.
:bro:id:`pm_attempt_set`: :bro:type:`event`             Generated for failed Portmapper requests of type *set*.
:bro:id:`pm_attempt_unset`: :bro:type:`event`           Generated for failed Portmapper requests of type *unset*.
:bro:id:`pm_bad_port`: :bro:type:`event`                Generated for Portmapper requests or replies that include an invalid port
                                                        number.
:bro:id:`pm_request_callit`: :bro:type:`event`          Generated for Portmapper request/reply dialogues of type *callit*.
:bro:id:`pm_request_dump`: :bro:type:`event`            Generated for Portmapper request/reply dialogues of type *dump*.
:bro:id:`pm_request_getport`: :bro:type:`event`         Generated for Portmapper request/reply dialogues of type *getport*.
:bro:id:`pm_request_null`: :bro:type:`event`            Generated for Portmapper requests of type *null*.
:bro:id:`pm_request_set`: :bro:type:`event`             Generated for Portmapper request/reply dialogues of type *set*.
:bro:id:`pm_request_unset`: :bro:type:`event`           Generated for Portmapper request/reply dialogues of type *unset*.
:bro:id:`rpc_call`: :bro:type:`event`                   Generated for RPC *call* messages.
:bro:id:`rpc_dialogue`: :bro:type:`event`               Generated for RPC request/reply *pairs*.
:bro:id:`rpc_reply`: :bro:type:`event`                  Generated for RPC *reply* messages.
======================================================= =========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: mount_proc_mnt

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`MOUNT3::info_t`, req: :bro:type:`MOUNT3::dirmntargs_t`, rep: :bro:type:`MOUNT3::mnt_reply_t`)

   Generated for MOUNT3 request/reply dialogues of type *mnt*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. bro:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: mount_proc_not_implemented

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`MOUNT3::info_t`, proc: :bro:type:`MOUNT3::proc_t`)

   Generated for MOUNT3 request/reply dialogues of a type that Bro's MOUNTv3
   analyzer does not implement.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :proc: The procedure called that Bro does not implement.
   
   .. bro:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: mount_proc_null

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`MOUNT3::info_t`)

   Generated for MOUNT3 request/reply dialogues of type *null*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   
   .. bro:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: mount_proc_umnt

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`MOUNT3::info_t`, req: :bro:type:`MOUNT3::dirmntargs_t`)

   Generated for MOUNT3 request/reply dialogues of type *umnt*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   
   .. bro:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: mount_proc_umnt_all

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`MOUNT3::info_t`, req: :bro:type:`MOUNT3::dirmntargs_t`)

   Generated for MOUNT3 request/reply dialogues of type *umnt_all*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   
   .. bro:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: mount_reply_status

   :Type: :bro:type:`event` (n: :bro:type:`connection`, info: :bro:type:`MOUNT3::info_t`)

   Generated for each MOUNT3 reply message received, reporting just the
   status included.
   

   :n: The connection.
   

   :info: Reports the status included in the reply.
   
   .. bro:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_create

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::diropargs_t`, rep: :bro:type:`NFS3::newobj_reply_t`)

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
   
   .. bro:see::  nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_getattr

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, fh: :bro:type:`string`, attrs: :bro:type:`NFS3::fattr_t`)

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
   
   .. bro:see:: nfs_proc_create  nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply file_mode
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_link

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::linkargs_t`, rep: :bro:type:`NFS3::link_reply_t`)

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
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      nfs_proc_symlink rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_lookup

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::diropargs_t`, rep: :bro:type:`NFS3::lookup_reply_t`)

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
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr  nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_mkdir

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::diropargs_t`, rep: :bro:type:`NFS3::newobj_reply_t`)

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
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_not_implemented

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, proc: :bro:type:`NFS3::proc_t`)

   Generated for NFSv3 request/reply dialogues of a type that Bro's NFSv3
   analyzer does not implement.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :proc: The procedure called that Bro does not implement.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_null nfs_proc_read nfs_proc_readdir nfs_proc_readlink nfs_proc_remove
      nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_null

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`)

   Generated for NFSv3 request/reply dialogues of type *null*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented  nfs_proc_read nfs_proc_readdir nfs_proc_readlink
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_read

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::readargs_t`, rep: :bro:type:`NFS3::read_reply_t`)

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
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_remove nfs_proc_rmdir
      nfs_proc_write nfs_reply_status rpc_call rpc_dialogue rpc_reply
      NFS3::return_data NFS3::return_data_first_only NFS3::return_data_max
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_readdir

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::readdirargs_t`, rep: :bro:type:`NFS3::readdir_reply_t`)

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
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readlink
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_readlink

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, fh: :bro:type:`string`, rep: :bro:type:`NFS3::readlink_reply_t`)

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
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      nfs_proc_symlink rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_remove

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::diropargs_t`, rep: :bro:type:`NFS3::delobj_reply_t`)

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
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink  nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_rename

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::renameopargs_t`, rep: :bro:type:`NFS3::renameobj_reply_t`)

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
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rename nfs_proc_write
      nfs_reply_status rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_rmdir

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::diropargs_t`, rep: :bro:type:`NFS3::delobj_reply_t`)

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
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove  nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_sattr

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::sattrargs_t`, rep: :bro:type:`NFS3::sattr_reply_t`)

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
   
   .. bro:see:: nfs_proc_create  nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply file_mode
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_symlink

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::symlinkargs_t`, rep: :bro:type:`NFS3::newobj_reply_t`)

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
   
   .. bro:see:: nfs_proc_create  nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      nfs_proc_link rpc_call rpc_dialogue rpc_reply file_mode
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_write

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::writeargs_t`, rep: :bro:type:`NFS3::write_reply_t`)

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
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir  nfs_reply_status rpc_call
      rpc_dialogue rpc_reply NFS3::return_data NFS3::return_data_first_only
      NFS3::return_data_max
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_reply_status

   :Type: :bro:type:`event` (n: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`)

   Generated for each NFSv3 reply message received, reporting just the
   status included.
   

   :n: The connection.
   

   :info: Reports the status included in the reply.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_attempt_callit

   :Type: :bro:type:`event` (r: :bro:type:`connection`, status: :bro:type:`rpc_status`, call: :bro:type:`pm_callit_request`)

   Generated for failed Portmapper requests of type *callit*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   

   :call: The argument to the original request.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset
      pm_attempt_getport pm_attempt_dump pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_attempt_dump

   :Type: :bro:type:`event` (r: :bro:type:`connection`, status: :bro:type:`rpc_status`)

   Generated for failed Portmapper requests of type *dump*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset
      pm_attempt_getport pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_attempt_getport

   :Type: :bro:type:`event` (r: :bro:type:`connection`, status: :bro:type:`rpc_status`, pr: :bro:type:`pm_port_request`)

   Generated for failed Portmapper requests of type *getport*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   

   :pr: The argument to the original request.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_attempt_null

   :Type: :bro:type:`event` (r: :bro:type:`connection`, status: :bro:type:`rpc_status`)

   Generated for failed Portmapper requests of type *null*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_set pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_attempt_set

   :Type: :bro:type:`event` (r: :bro:type:`connection`, status: :bro:type:`rpc_status`, m: :bro:type:`pm_mapping`)

   Generated for failed Portmapper requests of type *set*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   

   :m: The argument to the original request.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_attempt_unset

   :Type: :bro:type:`event` (r: :bro:type:`connection`, status: :bro:type:`rpc_status`, m: :bro:type:`pm_mapping`)

   Generated for failed Portmapper requests of type *unset*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   

   :m: The argument to the original request.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_bad_port

   :Type: :bro:type:`event` (r: :bro:type:`connection`, bad_p: :bro:type:`count`)

   Generated for Portmapper requests or replies that include an invalid port
   number. Since ports are represented by unsigned 4-byte integers, they can
   stray outside the allowed range of 0--65535 by being >= 65536. If so, this
   event is generated.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :bad_p: The invalid port value.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset
      pm_attempt_getport pm_attempt_dump pm_attempt_callit rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_request_callit

   :Type: :bro:type:`event` (r: :bro:type:`connection`, call: :bro:type:`pm_callit_request`, p: :bro:type:`port`)

   Generated for Portmapper request/reply dialogues of type *callit*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :call: The argument to the request.
   

   :p: The port value returned by the call.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_attempt_null
      pm_attempt_set pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_request_dump

   :Type: :bro:type:`event` (r: :bro:type:`connection`, m: :bro:type:`pm_mappings`)

   Generated for Portmapper request/reply dialogues of type *dump*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :m: The mappings returned by the server.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_callit pm_attempt_null
      pm_attempt_set pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_request_getport

   :Type: :bro:type:`event` (r: :bro:type:`connection`, pr: :bro:type:`pm_port_request`, p: :bro:type:`port`)

   Generated for Portmapper request/reply dialogues of type *getport*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :pr: The argument to the request.
   

   :p: The port returned by the server.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_request_null

   :Type: :bro:type:`event` (r: :bro:type:`connection`)

   Generated for Portmapper requests of type *null*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   
   .. bro:see:: pm_request_set pm_request_unset pm_request_getport
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_request_set

   :Type: :bro:type:`event` (r: :bro:type:`connection`, m: :bro:type:`pm_mapping`, success: :bro:type:`bool`)

   Generated for Portmapper request/reply dialogues of type *set*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :m: The argument to the request.
   

   :success: True if the request was successful, according to the corresponding
            reply. If no reply was seen, this will be false once the request
            times out.
   
   .. bro:see:: pm_request_null pm_request_unset pm_request_getport
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_request_unset

   :Type: :bro:type:`event` (r: :bro:type:`connection`, m: :bro:type:`pm_mapping`, success: :bro:type:`bool`)

   Generated for Portmapper request/reply dialogues of type *unset*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :m: The argument to the request.
   

   :success: True if the request was successful, according to the corresponding
            reply. If no reply was seen, this will be false once the request
            times out.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_getport
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: rpc_call

   :Type: :bro:type:`event` (c: :bro:type:`connection`, xid: :bro:type:`count`, prog: :bro:type:`count`, ver: :bro:type:`count`, proc: :bro:type:`count`, call_len: :bro:type:`count`)

   Generated for RPC *call* messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ONC_RPC>`__ for more information
   about the ONC RPC protocol.
   

   :c: The connection.
   

   :xid: The transaction identifier allowing to match requests with replies.
   

   :prog: The remote program to call.
   

   :ver: The version of the remote program to call.
   

   :proc: The procedure of the remote program to call.
   

   :call_len: The size of the *call_body* PDU.
   
   .. bro:see::  rpc_dialogue rpc_reply dce_rpc_bind dce_rpc_message dce_rpc_request
      dce_rpc_response rpc_timeout
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: rpc_dialogue

   :Type: :bro:type:`event` (c: :bro:type:`connection`, prog: :bro:type:`count`, ver: :bro:type:`count`, proc: :bro:type:`count`, status: :bro:type:`rpc_status`, start_time: :bro:type:`time`, call_len: :bro:type:`count`, reply_len: :bro:type:`count`)

   Generated for RPC request/reply *pairs*. The RPC analyzer associates request
   and reply by their transaction identifiers and raises this event once both
   have been seen. If there's not a reply, this event will still be generated
   eventually on timeout. In that case, *status* will be set to
   :bro:enum:`RPC_TIMEOUT`.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ONC_RPC>`__ for more information
   about the ONC RPC protocol.
   

   :c: The connection.
   

   :prog: The remote program to call.
   

   :ver: The version of the remote program to call.
   

   :proc: The procedure of the remote program to call.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   

   :start_time: The time when the *call* was seen.
   

   :call_len: The size of the *call_body* PDU.
   

   :reply_len: The size of the *reply_body* PDU.
   
   .. bro:see:: rpc_call rpc_reply dce_rpc_bind dce_rpc_message dce_rpc_request
      dce_rpc_response rpc_timeout
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: rpc_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, xid: :bro:type:`count`, status: :bro:type:`rpc_status`, reply_len: :bro:type:`count`)

   Generated for RPC *reply* messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ONC_RPC>`__ for more information
   about the ONC RPC protocol.
   

   :c: The connection.
   

   :xid: The transaction identifier allowing to match requests with replies.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   

   :reply_len: The size of the *reply_body* PDU.
   
   .. bro:see:: rpc_call rpc_dialogue  dce_rpc_bind dce_rpc_message dce_rpc_request
      dce_rpc_response rpc_timeout
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.


