zeek_add_plugin(
    Zeek RPC
    SOURCES RPC.cc NFS.cc MOUNT.cc Portmap.cc XDR.cc Plugin.cc
    BIFS consts.bif events.bif)
