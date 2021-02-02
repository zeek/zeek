// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/protocol/rpc/RPC.h"

namespace zeek::analyzer::rpc {
namespace detail {

class MOUNT_Interp : public RPC_Interpreter {
public:
	explicit MOUNT_Interp(analyzer::Analyzer* arg_analyzer) : RPC_Interpreter(arg_analyzer) { }

protected:
	bool RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n) override;
	bool RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status rpc_status,
				const u_char*& buf, int& n, double start_time,
				double last_time, int reply_len) override;

	// Returns a new arg list that already has a conn_val, rpc_status and
	// mount_status. These are the first parameters for each mount_* event
	// ...
	Args event_common_vl(RPC_CallInfo *c, BifEnum::rpc_status rpc_status,
				BifEnum::MOUNT3::status_t mount_status,
				double rep_start_time, double rep_last_time,
				int reply_len, int extra_elements);

	// These methods parse the appropriate MOUNTv3 "type" out of buf. If
	// there are any errors (i.e., buffer to short, etc), buf will be set
	// to 0. However, the methods might still return an allocated Val * !
	// So, you might want to Unref() the Val if buf is 0. Method names
	// are based on the type names of RFC 1813.
	EnumValPtr   mount3_auth_flavor(const u_char*& buf, int& n);
	StringValPtr mount3_fh(const u_char*& buf, int& n);
	RecordValPtr mount3_dirmntargs(const u_char*&buf, int &n);
	StringValPtr mount3_filename(const u_char*& buf, int& n);

	RecordValPtr mount3_mnt_reply(const u_char*& buf, int& n, BifEnum::MOUNT3::status_t status);
};

} // namespace detail

class MOUNT_Analyzer : public RPC_Analyzer {
public:
	explicit MOUNT_Analyzer(Connection* conn);
	void Init() override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new MOUNT_Analyzer(conn); }
};

} // namespace zeek::analyzer::rpc
