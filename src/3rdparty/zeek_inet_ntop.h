#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>

const char *
zeek_inet_ntop(int af, const void * __restrict src, char * __restrict dst,
    socklen_t size);

#ifdef __cplusplus
}
#endif
