include(CheckIncludeFiles)
include(CheckStructHasMember)

check_include_files(getopt.h HAVE_GETOPT_H)
check_include_files(magic.h HAVE_MAGIC_H)
check_include_files(memory.h HAVE_MEMORY_H)
check_include_files("sys/socket.h;netinet/in.h;net/if.h;netinet/if_ether.h"
                    HAVE_NETINET_IF_ETHER_H)
check_include_files("sys/socket.h;netinet/in.h;net/if.h;netinet/ip6.h"
                    HAVE_NETINET_IP6_H)
check_include_files("sys/socket.h;net/if.h;net/ethernet.h" HAVE_NET_ETHERNET_H)
check_include_files(sys/ethernet.h HAVE_SYS_ETHERNET_H)
check_include_files(sys/time.h HAVE_SYS_TIME_H)
check_include_files("time.h;sys/time.h" TIME_WITH_SYS_TIME)
check_include_files(os-proto.h HAVE_OS_PROTO_H)

check_struct_has_member(HISTORY_STATE entries "stdio.h;readline/readline.h"
                        HAVE_READLINE_HISTORY_ENTRIES)
check_include_files("stdio.h;readline/readline.h" HAVE_READLINE_READLINE_H)
check_include_files("stdio.h;readline/history.h" HAVE_READLINE_HISTORY_H)

if (HAVE_READLINE_READLINE_H AND
    HAVE_READLINE_HISTORY_H AND
    HAVE_READLINE_HISTORY_ENTRIES)
    set(HAVE_READLINE true)
endif ()

check_struct_has_member("struct sockaddr_in" sin_len "netinet/in.h" SIN_LEN)
