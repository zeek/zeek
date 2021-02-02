// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/protocol/rpc/RPC.h"
#include "zeek/NetVar.h"

namespace zeek::analyzer::rpc {
namespace detail {

class NFS_Interp : public RPC_Interpreter {
public:
	explicit NFS_Interp(analyzer::Analyzer* arg_analyzer) : RPC_Interpreter(arg_analyzer) { }

protected:
	bool RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n) override;
	bool RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status rpc_status,
				const u_char*& buf, int& n, double start_time,
				double last_time, int reply_len) override;

	// Returns a new val_list that already has a conn_val, rpc_status and
	// nfs_status. These are the first parameters for each nfs_* event
	// ...
	Args event_common_vl(RPC_CallInfo *c, BifEnum::rpc_status rpc_status,
				BifEnum::NFS3::status_t nfs_status,
				double rep_start_time, double rep_last_time,
				int reply_len, int extra_elements);

	// These methods parse the appropriate NFSv3 "type" out of buf. If
	// there are any errors (i.e., buffer to short, etc), buf will be set
	// to 0. However, the methods might still return an allocated Val * !
	// So, you might want to Unref() the Val if buf is 0. Method names
	// are based on the type names of RFC 1813.
	StringValPtr nfs3_fh(const u_char*& buf, int& n);
	RecordValPtr nfs3_fattr(const u_char*& buf, int& n);
	RecordValPtr nfs3_sattr(const u_char*& buf, int& n);
	EnumValPtr nfs3_ftype(const u_char*& buf, int& n);
	EnumValPtr nfs3_time_how(const u_char*& buf, int& n);
	RecordValPtr nfs3_wcc_attr(const u_char*& buf, int& n);
	RecordValPtr nfs3_diropargs(const u_char*&buf, int &n);
	RecordValPtr nfs3_symlinkdata(const u_char*& buf, int& n);
	RecordValPtr nfs3_renameopargs(const u_char*&buf, int &n);
	StringValPtr nfs3_filename(const u_char*& buf, int& n);
	RecordValPtr nfs3_linkargs(const u_char*& buf, int& n);
	RecordValPtr nfs3_symlinkargs(const u_char*& buf, int& n);
	RecordValPtr nfs3_sattrargs(const u_char*& buf, int& n);
	StringValPtr nfs3_nfspath(const u_char*& buf, int& n)
		{
		return nfs3_filename(buf,n);
		}

	RecordValPtr nfs3_post_op_attr(const u_char*&buf, int &n);	// Return 0 or an fattr
	RecordValPtr nfs3_pre_op_attr(const u_char*&buf, int &n);	// Return 0 or an wcc_attr
	RecordValPtr nfs3_sattr_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status);
	RecordValPtr nfs3_lookup_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status);
	RecordValPtr nfs3_readargs(const u_char*& buf, int& n);
	RecordValPtr nfs3_read_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status, bro_uint_t offset);
	RecordValPtr nfs3_readlink_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status);
	RecordValPtr nfs3_link_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status);
	RecordValPtr nfs3_writeargs(const u_char*& buf, int& n);
	EnumValPtr nfs3_stable_how(const u_char*& buf, int& n);
	RecordValPtr nfs3_write_reply(const u_char*& buf, int& n, BifEnum::NFS3::status_t status);
	RecordValPtr nfs3_newobj_reply(const u_char*& buf, int&n, BifEnum::NFS3::status_t status);
	RecordValPtr nfs3_delobj_reply(const u_char*& buf, int& n);
	RecordValPtr nfs3_renameobj_reply(const u_char*& buf, int& n);
	StringValPtr nfs3_post_op_fh(const u_char*& buf, int& n);
	RecordValPtr nfs3_readdirargs(bool isplus, const u_char*& buf, int&n);
	RecordValPtr nfs3_readdir_reply(bool isplus, const u_char*& buf, int&n, BifEnum::NFS3::status_t status);

	// Consumes the file data in the RPC message. Depending on NFS::return_data* consts
	// in bro.init returns NULL or the data as string val:
	//   * offset is the offset of the read/write call
	//   * size is the amount of bytes read (or requested to be written),
	StringValPtr nfs3_file_data(const u_char*& buf, int& n, uint64_t offset, int size);

	ValPtr ExtractUint32(const u_char*& buf, int& n);
	ValPtr ExtractUint64(const u_char*& buf, int& n);
	ValPtr ExtractTime(const u_char*& buf, int& n);
	ValPtr ExtractInterval(const u_char*& buf, int& n);
	ValPtr ExtractBool(const u_char*& buf, int& n);
};

} // namespace detail

class NFS_Analyzer : public RPC_Analyzer {
public:
	explicit NFS_Analyzer(Connection* conn);
	void Init() override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new NFS_Analyzer(conn); }
};

} // namespace zeek::analyzer::rpc
