#pragma once

#ifdef __cplusplus
extern "C"
	{
#endif

#include <sys/socket.h>
#include <sys/types.h>

	const char* bro_inet_ntop(int af, const void* __restrict src, char* __restrict dst,
	                          socklen_t size);

#ifdef __cplusplus
	}
#endif
