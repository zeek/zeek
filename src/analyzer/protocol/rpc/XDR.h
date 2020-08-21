// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h>
#include <netinet/in.h>

#include "util.h"

namespace zeek::analyzer::rpc {

extern uint32_t extract_XDR_uint32(const u_char*& buf, int& len);
extern uint64_t extract_XDR_uint64(const u_char*& buf, int& len);
extern double extract_XDR_time(const u_char*& buf, int& len);
extern const u_char* extract_XDR_opaque(const u_char*& buf, int& len,
					int& n, int max_len=8192, bool short_buf_ok=false);
extern const u_char* extract_XDR_opaque_fixed(const u_char*& buf, int& len, int n);
extern uint32_t skip_XDR_opaque_auth(const u_char*& buf, int& len);

} // namespace zeek::analyzer::rpc

namespace analyzer::rpc {

constexpr auto extract_XDR_uint32 [[deprecated("Remove in v4.1. Use zeek::analyzer::rpc::extract_XDR_uint32.")]] = zeek::analyzer::rpc::extract_XDR_uint32;
constexpr auto extract_XDR_uint64 [[deprecated("Remove in v4.1. Use zeek::analyzer::rpc::extract_XDR_uint64.")]] = zeek::analyzer::rpc::extract_XDR_uint64;
constexpr auto extract_XDR_time [[deprecated("Remove in v4.1. Use zeek::analyzer::rpc::extract_XDR_time.")]] = zeek::analyzer::rpc::extract_XDR_time;
constexpr auto extract_XDR_opaque [[deprecated("Remove in v4.1. Use zeek::analyzer::rpc::extract_XDR_opaque.")]] = zeek::analyzer::rpc::extract_XDR_opaque;
constexpr auto extract_XDR_opaque_fixed [[deprecated("Remove in v4.1. Use zeek::analyzer::rpc::extract_XDR_opaque_fixed.")]] = zeek::analyzer::rpc::extract_XDR_opaque_fixed;
constexpr auto skip_XDR_opaque_auth [[deprecated("Remove in v4.1. Use zeek::analyzer::rpc::skip_XDR_opaque_auth.")]] = zeek::analyzer::rpc::skip_XDR_opaque_auth;

} // namespace analyzer::rpc
