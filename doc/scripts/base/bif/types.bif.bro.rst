:tocdepth: 3

base/bif/types.bif.bro
======================
.. bro:namespace:: GLOBAL
.. bro:namespace:: MOUNT3
.. bro:namespace:: NFS3
.. bro:namespace:: Reporter
.. bro:namespace:: Tunnel

Declaration of various types that the Bro core uses internally.

:Namespaces: GLOBAL, MOUNT3, NFS3, Reporter, Tunnel

Summary
~~~~~~~
Types
#####
=================================================== =
:bro:type:`MOUNT3::auth_flavor_t`: :bro:type:`enum` 
:bro:type:`MOUNT3::proc_t`: :bro:type:`enum`        
:bro:type:`MOUNT3::status_t`: :bro:type:`enum`      
:bro:type:`NFS3::createmode_t`: :bro:type:`enum`    
:bro:type:`NFS3::file_type_t`: :bro:type:`enum`     
:bro:type:`NFS3::proc_t`: :bro:type:`enum`          
:bro:type:`NFS3::stable_how_t`: :bro:type:`enum`    
:bro:type:`NFS3::status_t`: :bro:type:`enum`        
:bro:type:`NFS3::time_how_t`: :bro:type:`enum`      
:bro:type:`Reporter::Level`: :bro:type:`enum`       
:bro:type:`Tunnel::Type`: :bro:type:`enum`          
:bro:type:`layer3_proto`: :bro:type:`enum`          
:bro:type:`link_encap`: :bro:type:`enum`            
:bro:type:`rpc_status`: :bro:type:`enum`            
=================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: MOUNT3::auth_flavor_t

   :Type: :bro:type:`enum`

      .. bro:enum:: MOUNT3::AUTH_NULL MOUNT3::auth_flavor_t

      .. bro:enum:: MOUNT3::AUTH_UNIX MOUNT3::auth_flavor_t

      .. bro:enum:: MOUNT3::AUTH_SHORT MOUNT3::auth_flavor_t

      .. bro:enum:: MOUNT3::AUTH_DES MOUNT3::auth_flavor_t


.. bro:type:: MOUNT3::proc_t

   :Type: :bro:type:`enum`

      .. bro:enum:: MOUNT3::PROC_NULL MOUNT3::proc_t

      .. bro:enum:: MOUNT3::PROC_MNT MOUNT3::proc_t

      .. bro:enum:: MOUNT3::PROC_DUMP MOUNT3::proc_t

      .. bro:enum:: MOUNT3::PROC_UMNT MOUNT3::proc_t

      .. bro:enum:: MOUNT3::PROC_UMNT_ALL MOUNT3::proc_t

      .. bro:enum:: MOUNT3::PROC_EXPORT MOUNT3::proc_t

      .. bro:enum:: MOUNT3::PROC_END_OF_PROCS MOUNT3::proc_t


.. bro:type:: MOUNT3::status_t

   :Type: :bro:type:`enum`

      .. bro:enum:: MOUNT3::MNT3_OK MOUNT3::status_t

      .. bro:enum:: MOUNT3::MNT3ERR_PERM MOUNT3::status_t

      .. bro:enum:: MOUNT3::MNT3ERR_NOENT MOUNT3::status_t

      .. bro:enum:: MOUNT3::MNT3ERR_IO MOUNT3::status_t

      .. bro:enum:: MOUNT3::MNT3ERR_ACCES MOUNT3::status_t

      .. bro:enum:: MOUNT3::MNT3ERR_NOTDIR MOUNT3::status_t

      .. bro:enum:: MOUNT3::MNT3ERR_INVAL MOUNT3::status_t

      .. bro:enum:: MOUNT3::MNT3ERR_NAMETOOLONG MOUNT3::status_t

      .. bro:enum:: MOUNT3::MNT3ERR_NOTSUPP MOUNT3::status_t

      .. bro:enum:: MOUNT3::MNT3ERR_SERVERFAULT MOUNT3::status_t

      .. bro:enum:: MOUNT3::MOUNT3ERR_UNKNOWN MOUNT3::status_t


.. bro:type:: NFS3::createmode_t

   :Type: :bro:type:`enum`

      .. bro:enum:: NFS3::UNCHECKED NFS3::createmode_t

      .. bro:enum:: NFS3::GUARDED NFS3::createmode_t

      .. bro:enum:: NFS3::EXCLUSIVE NFS3::createmode_t


.. bro:type:: NFS3::file_type_t

   :Type: :bro:type:`enum`

      .. bro:enum:: NFS3::FTYPE_REG NFS3::file_type_t

      .. bro:enum:: NFS3::FTYPE_DIR NFS3::file_type_t

      .. bro:enum:: NFS3::FTYPE_BLK NFS3::file_type_t

      .. bro:enum:: NFS3::FTYPE_CHR NFS3::file_type_t

      .. bro:enum:: NFS3::FTYPE_LNK NFS3::file_type_t

      .. bro:enum:: NFS3::FTYPE_SOCK NFS3::file_type_t

      .. bro:enum:: NFS3::FTYPE_FIFO NFS3::file_type_t


.. bro:type:: NFS3::proc_t

   :Type: :bro:type:`enum`

      .. bro:enum:: NFS3::PROC_NULL NFS3::proc_t

      .. bro:enum:: NFS3::PROC_GETATTR NFS3::proc_t

      .. bro:enum:: NFS3::PROC_SETATTR NFS3::proc_t

      .. bro:enum:: NFS3::PROC_LOOKUP NFS3::proc_t

      .. bro:enum:: NFS3::PROC_ACCESS NFS3::proc_t

      .. bro:enum:: NFS3::PROC_READLINK NFS3::proc_t

      .. bro:enum:: NFS3::PROC_READ NFS3::proc_t

      .. bro:enum:: NFS3::PROC_WRITE NFS3::proc_t

      .. bro:enum:: NFS3::PROC_CREATE NFS3::proc_t

      .. bro:enum:: NFS3::PROC_MKDIR NFS3::proc_t

      .. bro:enum:: NFS3::PROC_SYMLINK NFS3::proc_t

      .. bro:enum:: NFS3::PROC_MKNOD NFS3::proc_t

      .. bro:enum:: NFS3::PROC_REMOVE NFS3::proc_t

      .. bro:enum:: NFS3::PROC_RMDIR NFS3::proc_t

      .. bro:enum:: NFS3::PROC_RENAME NFS3::proc_t

      .. bro:enum:: NFS3::PROC_LINK NFS3::proc_t

      .. bro:enum:: NFS3::PROC_READDIR NFS3::proc_t

      .. bro:enum:: NFS3::PROC_READDIRPLUS NFS3::proc_t

      .. bro:enum:: NFS3::PROC_FSSTAT NFS3::proc_t

      .. bro:enum:: NFS3::PROC_FSINFO NFS3::proc_t

      .. bro:enum:: NFS3::PROC_PATHCONF NFS3::proc_t

      .. bro:enum:: NFS3::PROC_COMMIT NFS3::proc_t

      .. bro:enum:: NFS3::PROC_END_OF_PROCS NFS3::proc_t


.. bro:type:: NFS3::stable_how_t

   :Type: :bro:type:`enum`

      .. bro:enum:: NFS3::UNSTABLE NFS3::stable_how_t

      .. bro:enum:: NFS3::DATA_SYNC NFS3::stable_how_t

      .. bro:enum:: NFS3::FILE_SYNC NFS3::stable_how_t


.. bro:type:: NFS3::status_t

   :Type: :bro:type:`enum`

      .. bro:enum:: NFS3::NFS3ERR_OK NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_PERM NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_NOENT NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_IO NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_NXIO NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_ACCES NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_EXIST NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_XDEV NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_NODEV NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_NOTDIR NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_ISDIR NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_INVAL NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_FBIG NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_NOSPC NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_ROFS NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_MLINK NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_NAMETOOLONG NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_NOTEMPTY NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_DQUOT NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_STALE NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_REMOTE NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_BADHANDLE NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_NOT_SYNC NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_BAD_COOKIE NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_NOTSUPP NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_TOOSMALL NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_SERVERFAULT NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_BADTYPE NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_JUKEBOX NFS3::status_t

      .. bro:enum:: NFS3::NFS3ERR_UNKNOWN NFS3::status_t


.. bro:type:: NFS3::time_how_t

   :Type: :bro:type:`enum`

      .. bro:enum:: NFS3::DONT_CHANGE NFS3::time_how_t

      .. bro:enum:: NFS3::SET_TO_SERVER_TIME NFS3::time_how_t

      .. bro:enum:: NFS3::SET_TO_CLIENT_TIME NFS3::time_how_t


.. bro:type:: Reporter::Level

   :Type: :bro:type:`enum`

      .. bro:enum:: Reporter::INFO Reporter::Level

      .. bro:enum:: Reporter::WARNING Reporter::Level

      .. bro:enum:: Reporter::ERROR Reporter::Level


.. bro:type:: Tunnel::Type

   :Type: :bro:type:`enum`

      .. bro:enum:: Tunnel::NONE Tunnel::Type

      .. bro:enum:: Tunnel::IP Tunnel::Type

      .. bro:enum:: Tunnel::AYIYA Tunnel::Type

      .. bro:enum:: Tunnel::TEREDO Tunnel::Type

      .. bro:enum:: Tunnel::SOCKS Tunnel::Type

      .. bro:enum:: Tunnel::GTPv1 Tunnel::Type

      .. bro:enum:: Tunnel::HTTP Tunnel::Type

      .. bro:enum:: Tunnel::GRE Tunnel::Type


.. bro:type:: layer3_proto

   :Type: :bro:type:`enum`

      .. bro:enum:: L3_IPV4 layer3_proto

      .. bro:enum:: L3_IPV6 layer3_proto

      .. bro:enum:: L3_ARP layer3_proto

      .. bro:enum:: L3_UNKNOWN layer3_proto


.. bro:type:: link_encap

   :Type: :bro:type:`enum`

      .. bro:enum:: LINK_ETHERNET link_encap

      .. bro:enum:: LINK_UNKNOWN link_encap


.. bro:type:: rpc_status

   :Type: :bro:type:`enum`

      .. bro:enum:: RPC_SUCCESS rpc_status

      .. bro:enum:: RPC_PROG_UNAVAIL rpc_status

      .. bro:enum:: RPC_PROG_MISMATCH rpc_status

      .. bro:enum:: RPC_PROC_UNAVAIL rpc_status

      .. bro:enum:: RPC_GARBAGE_ARGS rpc_status

      .. bro:enum:: RPC_SYSTEM_ERR rpc_status

      .. bro:enum:: RPC_TIMEOUT rpc_status

      .. bro:enum:: RPC_VERS_MISMATCH rpc_status

      .. bro:enum:: RPC_AUTH_ERROR rpc_status

      .. bro:enum:: RPC_UNKNOWN_ERROR rpc_status



