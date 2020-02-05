:tocdepth: 3

base/bif/types.bif.zeek
=======================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: MOUNT3
.. zeek:namespace:: NFS3
.. zeek:namespace:: Reporter
.. zeek:namespace:: Tunnel

Declaration of various types that the Zeek core uses internally.

:Namespaces: GLOBAL, MOUNT3, NFS3, Reporter, Tunnel

Summary
~~~~~~~
Types
#####
===================================================== =
:zeek:type:`MOUNT3::auth_flavor_t`: :zeek:type:`enum` 
:zeek:type:`MOUNT3::proc_t`: :zeek:type:`enum`        
:zeek:type:`MOUNT3::status_t`: :zeek:type:`enum`      
:zeek:type:`NFS3::createmode_t`: :zeek:type:`enum`    
:zeek:type:`NFS3::file_type_t`: :zeek:type:`enum`     
:zeek:type:`NFS3::proc_t`: :zeek:type:`enum`          
:zeek:type:`NFS3::stable_how_t`: :zeek:type:`enum`    
:zeek:type:`NFS3::status_t`: :zeek:type:`enum`        
:zeek:type:`NFS3::time_how_t`: :zeek:type:`enum`      
:zeek:type:`Reporter::Level`: :zeek:type:`enum`       
:zeek:type:`TableChange`: :zeek:type:`enum`           
:zeek:type:`Tunnel::Type`: :zeek:type:`enum`          
:zeek:type:`layer3_proto`: :zeek:type:`enum`          
:zeek:type:`link_encap`: :zeek:type:`enum`            
:zeek:type:`rpc_status`: :zeek:type:`enum`            
===================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: MOUNT3::auth_flavor_t

   :Type: :zeek:type:`enum`

      .. zeek:enum:: MOUNT3::AUTH_NULL MOUNT3::auth_flavor_t

      .. zeek:enum:: MOUNT3::AUTH_UNIX MOUNT3::auth_flavor_t

      .. zeek:enum:: MOUNT3::AUTH_SHORT MOUNT3::auth_flavor_t

      .. zeek:enum:: MOUNT3::AUTH_DES MOUNT3::auth_flavor_t


.. zeek:type:: MOUNT3::proc_t

   :Type: :zeek:type:`enum`

      .. zeek:enum:: MOUNT3::PROC_NULL MOUNT3::proc_t

      .. zeek:enum:: MOUNT3::PROC_MNT MOUNT3::proc_t

      .. zeek:enum:: MOUNT3::PROC_DUMP MOUNT3::proc_t

      .. zeek:enum:: MOUNT3::PROC_UMNT MOUNT3::proc_t

      .. zeek:enum:: MOUNT3::PROC_UMNT_ALL MOUNT3::proc_t

      .. zeek:enum:: MOUNT3::PROC_EXPORT MOUNT3::proc_t

      .. zeek:enum:: MOUNT3::PROC_END_OF_PROCS MOUNT3::proc_t


.. zeek:type:: MOUNT3::status_t

   :Type: :zeek:type:`enum`

      .. zeek:enum:: MOUNT3::MNT3_OK MOUNT3::status_t

      .. zeek:enum:: MOUNT3::MNT3ERR_PERM MOUNT3::status_t

      .. zeek:enum:: MOUNT3::MNT3ERR_NOENT MOUNT3::status_t

      .. zeek:enum:: MOUNT3::MNT3ERR_IO MOUNT3::status_t

      .. zeek:enum:: MOUNT3::MNT3ERR_ACCES MOUNT3::status_t

      .. zeek:enum:: MOUNT3::MNT3ERR_NOTDIR MOUNT3::status_t

      .. zeek:enum:: MOUNT3::MNT3ERR_INVAL MOUNT3::status_t

      .. zeek:enum:: MOUNT3::MNT3ERR_NAMETOOLONG MOUNT3::status_t

      .. zeek:enum:: MOUNT3::MNT3ERR_NOTSUPP MOUNT3::status_t

      .. zeek:enum:: MOUNT3::MNT3ERR_SERVERFAULT MOUNT3::status_t

      .. zeek:enum:: MOUNT3::MOUNT3ERR_UNKNOWN MOUNT3::status_t


.. zeek:type:: NFS3::createmode_t

   :Type: :zeek:type:`enum`

      .. zeek:enum:: NFS3::UNCHECKED NFS3::createmode_t

      .. zeek:enum:: NFS3::GUARDED NFS3::createmode_t

      .. zeek:enum:: NFS3::EXCLUSIVE NFS3::createmode_t


.. zeek:type:: NFS3::file_type_t

   :Type: :zeek:type:`enum`

      .. zeek:enum:: NFS3::FTYPE_REG NFS3::file_type_t

      .. zeek:enum:: NFS3::FTYPE_DIR NFS3::file_type_t

      .. zeek:enum:: NFS3::FTYPE_BLK NFS3::file_type_t

      .. zeek:enum:: NFS3::FTYPE_CHR NFS3::file_type_t

      .. zeek:enum:: NFS3::FTYPE_LNK NFS3::file_type_t

      .. zeek:enum:: NFS3::FTYPE_SOCK NFS3::file_type_t

      .. zeek:enum:: NFS3::FTYPE_FIFO NFS3::file_type_t


.. zeek:type:: NFS3::proc_t

   :Type: :zeek:type:`enum`

      .. zeek:enum:: NFS3::PROC_NULL NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_GETATTR NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_SETATTR NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_LOOKUP NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_ACCESS NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_READLINK NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_READ NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_WRITE NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_CREATE NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_MKDIR NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_SYMLINK NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_MKNOD NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_REMOVE NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_RMDIR NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_RENAME NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_LINK NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_READDIR NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_READDIRPLUS NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_FSSTAT NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_FSINFO NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_PATHCONF NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_COMMIT NFS3::proc_t

      .. zeek:enum:: NFS3::PROC_END_OF_PROCS NFS3::proc_t


.. zeek:type:: NFS3::stable_how_t

   :Type: :zeek:type:`enum`

      .. zeek:enum:: NFS3::UNSTABLE NFS3::stable_how_t

      .. zeek:enum:: NFS3::DATA_SYNC NFS3::stable_how_t

      .. zeek:enum:: NFS3::FILE_SYNC NFS3::stable_how_t


.. zeek:type:: NFS3::status_t

   :Type: :zeek:type:`enum`

      .. zeek:enum:: NFS3::NFS3ERR_OK NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_PERM NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_NOENT NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_IO NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_NXIO NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_ACCES NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_EXIST NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_XDEV NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_NODEV NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_NOTDIR NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_ISDIR NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_INVAL NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_FBIG NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_NOSPC NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_ROFS NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_MLINK NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_NAMETOOLONG NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_NOTEMPTY NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_DQUOT NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_STALE NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_REMOTE NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_BADHANDLE NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_NOT_SYNC NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_BAD_COOKIE NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_NOTSUPP NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_TOOSMALL NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_SERVERFAULT NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_BADTYPE NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_JUKEBOX NFS3::status_t

      .. zeek:enum:: NFS3::NFS3ERR_UNKNOWN NFS3::status_t


.. zeek:type:: NFS3::time_how_t

   :Type: :zeek:type:`enum`

      .. zeek:enum:: NFS3::DONT_CHANGE NFS3::time_how_t

      .. zeek:enum:: NFS3::SET_TO_SERVER_TIME NFS3::time_how_t

      .. zeek:enum:: NFS3::SET_TO_CLIENT_TIME NFS3::time_how_t


.. zeek:type:: Reporter::Level

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Reporter::INFO Reporter::Level

      .. zeek:enum:: Reporter::WARNING Reporter::Level

      .. zeek:enum:: Reporter::ERROR Reporter::Level


.. zeek:type:: TableChange

   :Type: :zeek:type:`enum`

      .. zeek:enum:: TABLE_ELEMENT_NEW TableChange

      .. zeek:enum:: TABLE_ELEMENT_CHANGED TableChange

      .. zeek:enum:: TABLE_ELEMENT_REMOVED TableChange

      .. zeek:enum:: TABLE_ELEMENT_EXPIRED TableChange


.. zeek:type:: Tunnel::Type

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Tunnel::NONE Tunnel::Type

      .. zeek:enum:: Tunnel::IP Tunnel::Type

      .. zeek:enum:: Tunnel::AYIYA Tunnel::Type

      .. zeek:enum:: Tunnel::TEREDO Tunnel::Type

      .. zeek:enum:: Tunnel::SOCKS Tunnel::Type

      .. zeek:enum:: Tunnel::GTPv1 Tunnel::Type

      .. zeek:enum:: Tunnel::HTTP Tunnel::Type

      .. zeek:enum:: Tunnel::GRE Tunnel::Type

      .. zeek:enum:: Tunnel::VXLAN Tunnel::Type


.. zeek:type:: layer3_proto

   :Type: :zeek:type:`enum`

      .. zeek:enum:: L3_IPV4 layer3_proto

      .. zeek:enum:: L3_IPV6 layer3_proto

      .. zeek:enum:: L3_ARP layer3_proto

      .. zeek:enum:: L3_UNKNOWN layer3_proto


.. zeek:type:: link_encap

   :Type: :zeek:type:`enum`

      .. zeek:enum:: LINK_ETHERNET link_encap

      .. zeek:enum:: LINK_UNKNOWN link_encap


.. zeek:type:: rpc_status

   :Type: :zeek:type:`enum`

      .. zeek:enum:: RPC_SUCCESS rpc_status

      .. zeek:enum:: RPC_PROG_UNAVAIL rpc_status

      .. zeek:enum:: RPC_PROG_MISMATCH rpc_status

      .. zeek:enum:: RPC_PROC_UNAVAIL rpc_status

      .. zeek:enum:: RPC_GARBAGE_ARGS rpc_status

      .. zeek:enum:: RPC_SYSTEM_ERR rpc_status

      .. zeek:enum:: RPC_TIMEOUT rpc_status

      .. zeek:enum:: RPC_VERS_MISMATCH rpc_status

      .. zeek:enum:: RPC_AUTH_ERROR rpc_status

      .. zeek:enum:: RPC_UNKNOWN_ERROR rpc_status



