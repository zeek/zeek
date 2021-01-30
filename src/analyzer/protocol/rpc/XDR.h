// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h>
#include <netinet/in.h>

#include "zeek/util.h"

namespace zeek::analyzer::rpc {

extern uint32_t extract_XDR_uint32(const u_char*& buf, int& len);
extern uint64_t extract_XDR_uint64(const u_char*& buf, int& len);
extern double extract_XDR_time(const u_char*& buf, int& len);
extern const u_char* extract_XDR_opaque(const u_char*& buf, int& len,
					int& n, int max_len=8192, bool short_buf_ok=false);
extern const u_char* extract_XDR_opaque_fixed(const u_char*& buf, int& len, int n);
extern uint32_t skip_XDR_opaque_auth(const u_char*& buf, int& len);

} // namespace zeek::analyzer::rpc
