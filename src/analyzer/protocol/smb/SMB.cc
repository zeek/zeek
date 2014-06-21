// See the file "COPYING" in the main distribution directory for copyright.

#include "NetVar.h"
#include "SMB.h"
#include "smb_pac.h"
#include "Val.h"
#include "Reporter.h"

#include "events.bif.h"

using namespace analyzer::smb;

namespace {
	const bool DEBUG_smb_ipc = true;
}

#define BYTEORDER_SWAP16(n) ((256 * ((n) & 0xff)) + ((n) >> 8))

enum SMB_Command {
#define SMB_COMMAND(name, value) name = value,
#include "SMB_COM.def"
#undef SMB_COMMAND
};

enum SMB_Transaction_Command {
	HOST_ANNOUNCEMENT = 1,
	ANNOUCEMENT_REQUEST = 2,
	REQUEST_ELECTION = 8,
	GET_BACKUP_LIST_REQUEST = 9,
	GET_BACKUP_LIST_RESPONSE = 10,
	BECOME_BACKUP_REQUEST = 11,
	DOMAIN_ANNOUNCEMENT = 12,
	MASTER_ANNOUNCEMENT = 13,
	RESET_BROWSER_STATE = 14,
	LOCAL_MASTER_ANNOUNCEMENT = 15,
};

const char* SMB_command_name[256];
StringVal* SMB_command_str[256];
const char* SMB_trans_command_name[256];
StringVal* SMB_trans_command_str[256];

static void init_SMB_command_name()
	{
	static int initialized = 0;
	if ( initialized )
		return;

	initialized = 1;

	for ( int i = 0; i < 256; ++i )
		{
		SMB_command_name[i] = "<unknown>";
		SMB_command_str[i] = 0;
		}

#define SMB_COMMAND(name, value) SMB_command_name[value] = #name;
#include "SMB_COM.def"
#undef SMB_COMMAND
#define SMB_COMMAND(name, value) SMB_trans_command_name[value] = #name;
	SMB_COMMAND(HOST_ANNOUNCEMENT, 1)
	SMB_COMMAND(ANNOUCEMENT_REQUEST, 2)
	SMB_COMMAND(REQUEST_ELECTION, 8)
	SMB_COMMAND(GET_BACKUP_LIST_REQUEST, 9)
	SMB_COMMAND(GET_BACKUP_LIST_RESPONSE, 10)
	SMB_COMMAND(BECOME_BACKUP_REQUEST, 11)
	SMB_COMMAND(DOMAIN_ANNOUNCEMENT, 12)
	SMB_COMMAND(MASTER_ANNOUNCEMENT, 13)
	SMB_COMMAND(RESET_BROWSER_STATE, 14)
	SMB_COMMAND(LOCAL_MASTER_ANNOUNCEMENT, 15)

	}

StringVal* get_SMB_command_str(int cmd)
	{
	if ( ! SMB_command_str[cmd] )
		SMB_command_str[cmd] = new StringVal(SMB_command_name[cmd]);

	return SMB_command_str[cmd];
	}

// ### TODO: the list of IPC pipes needs a lot of expansion.
static int lookup_IPC_name(BroString* name)
	{
	static const char* IPC_pipe_names[] = {
		"\\locator", "\\epmapper", "\\samr", "\\lsarpc", 0
	};

	for ( int i = 0; IPC_pipe_names[i]; ++i )
		{
		if ( size_t(name->Len()) == strlen(IPC_pipe_names[i]) &&
		     strncmp((const char*) name->Bytes(),
			     IPC_pipe_names[i], name->Len()) == 0 )
			return i + 1;
		}

	return IPC_NONE;
	}

SMB_Session::SMB_Session(analyzer::Analyzer* arg_analyzer)
	{
	analyzer = arg_analyzer;
	req_cmd = 0;
	smb_mailslot_prot = false;
	smb_pipe_prot = false;
	dce_rpc_session = 0;
	init_SMB_command_name();

	// Strangely, one does not have to connect to IPC$ before
	// making DCE/RPC calls. So we assume that it's always IPC
	// unless confirmed otherwise.

	is_IPC = true;
	IPC_pipe = IPC_NONE;

	transaction_name = 0;
	transaction_subcmd = 0;

	andx_[0] = andx_[1] = 0;
	set_andx(0, 0);
	set_andx(1, 0);

	}

SMB_Session::~SMB_Session()
	{
	binpac::Unref(andx_[0]);
	binpac::Unref(andx_[1]);
	Unref(transaction_name);
	delete dce_rpc_session;
	}

void SMB_Session::set_andx(int is_orig, binpac::SMB::SMB_andx* andx)
	{
	int ind = is_orig ? 1 : 0;
	if ( andx )
		andx->Ref();

	binpac::Unref(andx_[ind]);

	andx_[ind] = andx;
	}

void SMB_Session::Deliver(int is_orig, int len, const u_char* data)
	{
	if ( len == 0 )
		return;

	try
		{
		const u_char* data_start = data;
		const u_char* data_end = data + len;

		binpac::SMB::SMB_header hdr;
		int hdr_len = hdr.Parse(data, data_end);

		data += hdr_len;

		int next_command = hdr.command();

		while ( data < data_end )
			{
			SMB_Body body(data, data_end);
			set_andx(is_orig, 0);
			ParseMessage(is_orig, next_command, hdr, body);

			int next = AndxOffset(is_orig, next_command);
			if ( next <= 0 )
				break;

			//Weird(fmt("ANDX! at %d", next));
			const u_char* tmp = data_start + next;
			if ( data_start + next < data + body.length() )
				{
				Weird(fmt("ANDX buffer overlapping: next = %d, buffer_end = %" PRIuPTR, next, data + body.length() - data_start));
				break;
				}

			data = data_start + next;
			}
		}
	catch ( const binpac::Exception& e )
		{
		analyzer->Weird(e.msg().c_str());
		}
	}

void SMB_Session::ParseMessage(int is_orig, int cmd,
				binpac::SMB::SMB_header const& hdr,
				SMB_Body const& body)
	{
	if ( smb_message )
		{
		val_list* vl = new val_list;
		StringVal* cmd_str = get_SMB_command_str(cmd);
		Ref(cmd_str);

		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));
		vl->append(new Val(is_orig, TYPE_BOOL));
		vl->append(cmd_str);
		vl->append(new Val(body.length(), TYPE_COUNT));
		vl->append(new StringVal(body.length(),
					(const char*) body.data()));

		analyzer->ConnectionEvent(smb_message, vl);
		}

	if ( is_orig )
		req_cmd = cmd;

	// What if there's an error?
	// if ( hdr.status->status() || hdr.status->dos_error() )
	// The command code in the header might be right, but
	// the response is probably mangled :-(.

	int ci = hdr.status()->val_case_index();
	if ( (ci == 1 && hdr.status()->status()) ||
	     (ci == 0 && (hdr.status()->dos_error()->error_class() ||
			  hdr.status()->dos_error()->error())) )
		{
		unsigned int error = 0;

		switch ( ci ) {
		case 0:
			error = hdr.status()->dos_error()->error_class() << 24 ||
				hdr.status()->dos_error()->error();
			break;
		case 1:
			error = hdr.status()->status();
			break;
		}

		val_list* vl = new val_list;
		StringVal* cmd_str = get_SMB_command_str(cmd);
		Ref(cmd_str);

		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));
		vl->append(new Val(cmd, TYPE_COUNT));
		vl->append(cmd_str);
		vl->append(new StringVal(body.length(),
					(const char*) body.data()));

		analyzer->ConnectionEvent(smb_error, vl);

		// Is this the right behavior?
		return;
		}

	int ret = 0;
	switch ( cmd ) {
	case SMB_COM_TREE_CONNECT_ANDX:
		if ( is_orig )
			ret = ParseTreeConnectAndx(hdr, body);
		else
			ret = ParseAndx(is_orig, hdr, body);
		break;

	case SMB_COM_NT_CREATE_ANDX:
		if ( is_orig )
			ret = ParseNtCreateAndx(hdr, body);
		else
			ret = ParseAndx(is_orig, hdr, body);
		break;

	case SMB_COM_TRANSACTION:
	case SMB_COM_TRANSACTION2:
	case SMB_COM_TRANSACTION_SECONDARY:
	case SMB_COM_TRANSACTION2_SECONDARY:
		ret = ParseTransaction(is_orig, cmd, hdr, body);
		break;

	case SMB_COM_READ_ANDX:
		if ( is_orig )
			ret = ParseReadAndx(hdr, body);
		else
			ret = ParseReadAndxResponse(hdr, body);
		break;

	case SMB_COM_WRITE_ANDX:
		if ( is_orig )
			ret = ParseWriteAndx(hdr, body);
		else
			ret = ParseWriteAndxResponse(hdr, body);
		break;

	case SMB_COM_NEGOTIATE:
		if ( is_orig )
			ret = ParseNegotiate(hdr, body);
		else
			ret = ParseNegotiateResponse(hdr, body);
		break;

	case SMB_COM_CLOSE:
		ret = ParseClose(is_orig, hdr, body);
		break;

	case SMB_COM_TREE_DISCONNECT:
		ret = ParseTreeDisconnect(is_orig, hdr, body);
		break;

	case SMB_COM_LOGOFF_ANDX:
		if ( is_orig )
			ret = ParseLogoffAndx(is_orig, hdr, body);
		else
			ret = ParseAndx(is_orig, hdr, body);
		break;

	case SMB_COM_SESSION_SETUP_ANDX:
		if ( is_orig )
			ret = ParseSetupAndx(is_orig, hdr, body);
		else
			ret = ParseAndx(is_orig, hdr, body);
		break;

	default:
		Weird(fmt("unknown_SMB_command(0x%x)", cmd));
		break;
	}

	if ( ret == -1 )
		Weird("SMB_parsing_error");
	}

int SMB_Session::ParseNegotiate(binpac::SMB::SMB_header const& hdr,
				SMB_Body const& body)
	{
	binpac::SMB::SMB_negotiate msg;
	msg.Parse(body.data(), body.data() + body.length());

	if ( smb_com_negotiate )
		{
		TableVal* t = new TableVal(smb_negotiate);
		for ( int i = 0; i < int(msg.dialects()->size()); ++i )
			{
			binpac::SMB::SMB_dialect* d = (*msg.dialects())[i];
			BroString* tmp = ExtractString(d->dialectname());
			t->Assign(new Val(i, TYPE_COUNT), new StringVal(tmp));
			}

		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));
		vl->append(t);

		analyzer->ConnectionEvent(smb_com_negotiate, vl);
		}

	return 0;
	}

int SMB_Session::ParseNegotiateResponse(binpac::SMB::SMB_header const& hdr,
					SMB_Body const& body)
	{
	binpac::SMB::SMB_negotiate_response msg;
	msg.Parse(body.data(), body.data() + body.length());

	if ( smb_com_negotiate_response )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));
		vl->append(new Val(msg.dialect_index(), TYPE_COUNT));

		analyzer->ConnectionEvent(smb_com_negotiate_response, vl);
		}

	return 0;
	}

int SMB_Session::ParseSetupAndx(int is_orig, binpac::SMB::SMB_header const& hdr,
				SMB_Body const& body)
 	{
	// The binpac type depends on the negotiated server settings -
	// possibly we can just pick the "right" format here, and use that?

	if ( hdr.flags2() & 0x0800 )
		{
		binpac::SMB::SMB_setup_andx_ext msg(hdr.unicode());
		msg.Parse(body.data(), body.data() + body.length());
		set_andx(1, msg.andx());
		}
	else
		{
		binpac::SMB::SMB_setup_andx_basic msg(hdr.unicode());
		msg.Parse(body.data(), body.data() + body.length());
		set_andx(1, msg.andx());
		}

	if ( smb_com_setup_andx )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));

		analyzer->ConnectionEvent(smb_com_setup_andx, vl);
		}

	return 0;
	}

int SMB_Session::ParseClose(int is_orig, binpac::SMB::SMB_header const& hdr,
				SMB_Body const& body)
	{
	if ( smb_com_close )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));

		analyzer->ConnectionEvent(smb_com_close, vl);
		}

	return 0;
	}

int SMB_Session::ParseLogoffAndx(int is_orig,
					binpac::SMB::SMB_header const& hdr,
					SMB_Body const& body)
	{
 	binpac::SMB::SMB_generic_andx msg;
 	msg.Parse(body.data(), body.data() + body.length());
 	if ( msg.word_count() > 0 )
		set_andx(is_orig, msg.andx());

	if ( smb_com_logoff_andx )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));

		analyzer->ConnectionEvent(smb_com_logoff_andx, vl);
		}

 	return 0;
 	}
 
int SMB_Session::ParseAndx(int is_orig, binpac::SMB::SMB_header const& hdr,
				SMB_Body const& body)
	{
	// This is a generic ANDX event generator.  It passes the header
	// and the ANDX data out to the policy.
	try
		{
		binpac::SMB::SMB_generic_andx msg;
		msg.Parse(body.data(), body.data() + body.length());
		if ( msg.word_count() > 0 )
			set_andx(is_orig, msg.andx());

		if ( smb_com_generic_andx )
			{
			val_list* vl = new val_list;
			vl->append(analyzer->BuildConnVal());
			vl->append(BuildHeaderVal(hdr));
			vl->append(new StringVal(msg.data().length(),
					(char *) msg.data().begin()));

			analyzer->ConnectionEvent(smb_com_generic_andx, vl);
			}
		}
	catch ( const binpac::Exception& )
		{
		Weird("smb_andx_command_failed_to_parse");
		}

	return 0;
	}

int SMB_Session::ParseTreeConnectAndx(binpac::SMB::SMB_header const& hdr,
					SMB_Body const& body)
	{
	binpac::SMB::SMB_tree_connect_andx req(hdr.unicode());

	req.Parse(body.data(), body.data() + body.length());
	set_andx(1, req.andx());

	BroString* path = ExtractString(req.path());
	BroString* service = ExtractString(req.service());

	// Replicate path.
	BroString* norm_path = new BroString(path->Bytes(), path->Len(), 1);
	norm_path->ToUpper();

	RecordVal* r = new RecordVal(smb_tree_connect);
	r->Assign(0, new Val(req.flags(), TYPE_COUNT));
	r->Assign(1, new StringVal(req.password_length(),
					(const char*) req.password()));
	r->Assign(2, new StringVal(path));
	r->Assign(3, new StringVal(service));

	if ( strstr_n(norm_path->Len(), norm_path->Bytes(), 5,
		      (const u_char*) "\\IPC$") != -1 )
		is_IPC = true;	// TODO: change is_IPC to 0 on tree_disconnect
	else
		is_IPC = false;

	delete norm_path;

	if ( smb_com_tree_connect_andx )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));
		vl->append(r);

		analyzer->ConnectionEvent(smb_com_tree_connect_andx, vl);
		}
	else
		{
		delete path;
		delete service;
		}

	return 0;
	}

int SMB_Session::ParseTreeDisconnect(int is_orig,
					binpac::SMB::SMB_header const& hdr,
					SMB_Body const& body)
	{
	binpac::SMB::SMB_tree_disconnect msg(hdr.unicode());
	msg.Parse(body.data(), body.data() + body.length());

	if ( smb_com_nt_create_andx )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));

		analyzer->ConnectionEvent(smb_com_tree_disconnect, vl);
		}

	return 0;
	}

int SMB_Session::ParseNtCreateAndx(binpac::SMB::SMB_header const& hdr,
					SMB_Body const& body)
	{
	binpac::SMB::SMB_nt_create_andx req(hdr.unicode());
	req.Parse(body.data(), body.data() + body.length());
	set_andx(1, req.andx());

	BroString* name = ExtractString(req.name());

	IPC_pipe = (enum IPC_named_pipe) lookup_IPC_name(name);

	if ( smb_com_nt_create_andx )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));
		vl->append(new StringVal(name));

		analyzer->ConnectionEvent(smb_com_nt_create_andx, vl);
		}
	else
		delete name;

	return 0;
	}

int SMB_Session::ParseReadAndx(binpac::SMB::SMB_header const& hdr,
				SMB_Body const& body)
	{
	binpac::SMB::SMB_read_andx req;
	req.Parse(body.data(), body.data() + body.length());
	set_andx(1, req.andx());

	if ( smb_com_read_andx )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));
		vl->append(new StringVal(""));

		analyzer->ConnectionEvent(smb_com_read_andx, vl);
		}

	return 0;
	}

int SMB_Session::ParseReadAndxResponse(binpac::SMB::SMB_header const& hdr,
					SMB_Body const& body)
	{
	binpac::SMB::SMB_read_andx_response resp;
	resp.Parse(body.data(), body.data() + body.length());
	set_andx(0, resp.andx());

	int data_count = resp.data_length();
	const u_char* data = resp.data().begin();

	if ( smb_com_read_andx )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));
		vl->append(new StringVal(data_count, (const char*) data));

		analyzer->ConnectionEvent(smb_com_read_andx, vl);
		}

	CheckRPC(0, data_count, data);

	return 0;
	}

int SMB_Session::ParseWriteAndx(binpac::SMB::SMB_header const& hdr,
				SMB_Body const& body)
	{
	binpac::SMB::SMB_write_andx req;
	req.Parse(body.data(), body.data() + body.length());
	set_andx(1, req.andx());

	int data_count = req.data_length();
	const u_char* data = req.data().begin();

	if ( smb_com_write_andx )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));
		vl->append(new StringVal(data_count, (const char*) data));

		analyzer->ConnectionEvent(smb_com_write_andx, vl);
		}

	CheckRPC(1, data_count, data);

	return 0;
	}

int SMB_Session::ParseWriteAndxResponse(binpac::SMB::SMB_header const& hdr,
					SMB_Body const& body)
	{
	binpac::SMB::SMB_write_andx_response resp;
	resp.Parse(body.data(), body.data() + body.length());
	set_andx(0, resp.andx());

	if ( smb_com_write_andx )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));
		vl->append(new StringVal(""));

		analyzer->ConnectionEvent(smb_com_write_andx, vl);
		}

	return 0;
	}

int SMB_Session::TransactionEvent(EventHandlerPtr f, int is_orig,
				binpac::SMB::SMB_header const &hdr,
				binpac::SMB::SMB_transaction const &trans,
				int data_count,
				binpac::SMB::SMB_transaction_data* data)
	{
	if ( f )
		{
		val_list* vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));
		vl->append(BuildTransactionVal(trans));
		vl->append(BuildTransactionDataVal(data));
		vl->append(new Val(is_orig, TYPE_BOOL));

		analyzer->ConnectionEvent(f, vl);
		}

	else if ( smb_com_transaction )
		{ // generic transaction
		}

	return 0;
	}

int SMB_Session::TransactionEvent(EventHandlerPtr f, int is_orig,
			binpac::SMB::SMB_header const &hdr,
			binpac::SMB::SMB_transaction_secondary const &trans,
			int data_count, binpac::SMB::SMB_transaction_data* data)
	{
	if ( f )
		{
		val_list* vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));
		vl->append(BuildTransactionVal(trans));
		vl->append(BuildTransactionDataVal(data));
		vl->append(new Val(is_orig, TYPE_BOOL));

		analyzer->ConnectionEvent(f, vl);
		}

	else if ( smb_com_transaction )
		{ // generic transaction
		}

	return 0;
	}

int SMB_Session::TransactionEvent(EventHandlerPtr f, int is_orig,
			binpac::SMB::SMB_header const &hdr,
			binpac::SMB::SMB_transaction_response const &trans,
			int data_count, binpac::SMB::SMB_transaction_data* data)
	{
	if ( f )
		{
		val_list* vl = new val_list;

		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));
		vl->append(BuildTransactionVal(trans));
		vl->append(BuildTransactionDataVal(data));
		vl->append(new Val(is_orig, TYPE_BOOL));

		analyzer->ConnectionEvent(f, vl);
		}

	else if ( smb_com_transaction )
		{ // generic transaction
		}

	return 0;
	}

int SMB_Session::ParseTransaction(int is_orig, int cmd,
					binpac::SMB::SMB_header const& hdr,
					SMB_Body const& body)
	{
	switch ( cmd ) {
	case SMB_COM_TRANSACTION:
	case SMB_COM_TRANSACTION2:
	case SMB_COM_TRANSACTION_SECONDARY:
	case SMB_COM_TRANSACTION2_SECONDARY:
		break;

	default:
		reporter->AnalyzerError(analyzer,
		  "command mismatch for SMB_Session::ParseTransaction");
		return 0;
	}

	if ( ! is_orig )
		return ParseTransactionResponse(cmd, hdr, body);

	if ( cmd == SMB_COM_TRANSACTION || cmd == SMB_COM_TRANSACTION2 )
		return ParseTransactionRequest(cmd, hdr, body);

	return ParseTransactionSecondaryRequest(cmd, hdr, body);
	}

int SMB_Session::ParseTransactionRequest(int cmd,
					binpac::SMB::SMB_header const& hdr,
					SMB_Body const& body)
	{
	binpac::SMB::SMB_transaction trans(cmd == SMB_COM_TRANSACTION ? 1 : 2,
						hdr.unicode());

	trans.Parse(body.data(), body.data() + body.length());

	if ( transaction_name )
		{
		Unref(transaction_name);
		transaction_name = 0;
		}

	if ( cmd == SMB_COM_TRANSACTION )
		{
		binpac::SMB::SMB_transaction_data* trans_data = trans.data();

		//transaction_name = new StringVal(ExtractString(trans.name()));
		//if ( is_orig )
		//	Weird(fmt("smb_transaction subcmd: 0x%x", transaction_subcmd));

		if ( trans_data->val_case_index() ==
			binpac::SMB::SMB_MAILSLOT_BROWSE &&
		     trans_data->mailslot() )
			{ // Mailslot transaction event
			return TransactionEvent(smb_com_trans_mailslot, true,
				hdr, trans, trans.data_count(), trans.data());
			}

		else if ( trans_data->val_case_index() ==
				binpac::SMB::SMB_PIPE && trans_data->pipe() )
			{ // Pipe
			return TransactionEvent(smb_com_trans_pipe, true, hdr,
				trans, trans.data_count(), trans.data());
			}

		else if ( trans_data->val_case_index() ==
				binpac::SMB::SMB_RAP && trans_data->rap() )
			{ // Remote Administration Protocol
			return TransactionEvent(smb_com_trans_rap, true, hdr,
				trans, trans.data_count(), trans.data());
			}

		else
			{
			// SOME UNKNOWN TRANSACTION TYPE - COULD BE RPC STILL!
			if ( trans.data_count() > 0 && trans.setup_count() == 2 )
				{
				if ( CheckRPC(true, trans.data_count(),
					trans_data->pipe()->data().begin()) )
					{
					if ( cmd != SMB_COM_TRANSACTION ||
					     transaction_subcmd != 0x26 )
						Weird(fmt("RPC through unknown command: 0x%x/0x%x", cmd, transaction_subcmd));
					}
				}
			}
		}

	if ( cmd == SMB_COM_TRANSACTION2 )
		{
		switch ( transaction_subcmd ) {
		case 0x3: // QueryFSInfo
		case 0x5: // QueryPathInfo
		case 0x7: // QueryFileInfo
		case 0x8: // SetFileInfo
			break;

		case 0x10:
			// if ( is_orig )
			return ParseGetDFSReferral(hdr, trans.param_count(),
						trans.parameters().begin());

		default:
			// if ( is_orig )
			Weird(fmt("Unknown smb_transaction2 subcmd: 0x%x",
					transaction_subcmd));
			break;
		}
		}

	if ( smb_com_transaction )
		return TransactionEvent(smb_com_transaction, true, hdr,
					trans, trans.data_count(),
					trans.data());
	else
		return 0;

#if 0
	// TODO: LANMAN transaction uses the first u_short of
	// parameters as subcmd

	if ( trans.setup_count() > 0 )
		transaction_subcmd = (*trans.setup())[0];

	else if ( strncmp( transaction_name->CheckString(), "\\PIPE\\", 6 ) == 0 )
		transaction_subcmd = 0;

	else if ( strncmp( transaction_name->CheckString(), "\\MAILSLOT\\", 10 ) == 0 )
		transaction_subcmd = 0;

	else
		Weird("transaction_subcmd_missing");
#endif
	}

int SMB_Session::ParseTransactionSecondaryRequest(int cmd,
					binpac::SMB::SMB_header const& hdr,
					SMB_Body const& body)
	{
	binpac::SMB::SMB_transaction_secondary trans(hdr.unicode());
	trans.Parse(body.data(), body.data() + body.length());

	return TransactionEvent(smb_com_transaction2, true, hdr,
				trans, trans.data_count(), trans.data());
	}

int SMB_Session::ParseTransactionResponse(int cmd,
					binpac::SMB::SMB_header const& hdr,
					SMB_Body const& body)
	{
	binpac::SMB::SMB_transaction_response trans(hdr.unicode());
	trans.Parse(body.data(), body.data() + body.length());

	if ( body.word_count() == 0 )
		{ // interim response
		// Does the transaction get parsed correctly?!
		return TransactionEvent(smb_com_transaction, false, hdr,
					trans, 0, NULL);
		}

	return TransactionEvent(smb_com_transaction, false, hdr,
				trans, trans.data_count(), trans.data());
	}

int SMB_Session::ParseGetDFSReferral(binpac::SMB::SMB_header const& hdr,
					int param_count, const u_char* param)
	{
	binpac::SMB::SMB_get_dfs_referral req(hdr.unicode());
	req.Parse(param, param + param_count);

	if ( smb_get_dfs_referral )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(BuildHeaderVal(hdr));
		vl->append(new Val(req.max_referral_level(), TYPE_COUNT));
		vl->append(new StringVal(ExtractString(req.file_name())));

		analyzer->ConnectionEvent(smb_get_dfs_referral, vl);
		}

	return 0;
	}

int SMB_Session::AndxOffset(int is_orig, int& next_command) const
	{
	if ( ! andx(is_orig) )
		return -1;

	next_command = andx(is_orig)->command();
	if ( next_command != 0xff )
		return andx(is_orig)->offset();
	else
		return -1;
	}

void SMB_Session::Weird(const char* msg)
	{
	analyzer->Weird(msg);
	}

// Extract a NUL-terminated string from [data, data+len-1]. The
// input can be in Unicode (little endian), and the returned string
// will be in ASCII.  Note, Unicode strings have NUL characters
// at the end of them already.  Adding an additional NUL byte at
// the end leads to embedded-NUL warnings (CheckString() run time error).

BroString* SMB_Session::ExtractString(binpac::SMB::SMB_string const* s)
	{
	return s->unicode() ? ExtractString(s->u()) : ExtractString(s->a());
	}

BroString* SMB_Session::ExtractString(binpac::SMB::SMB_ascii_string const* s)
	{
	bool add_NUL = true;
	int n = s->size();

	if ( n > 0 && (*s)[n - 1] == '\0' )
		add_NUL = false;	// already has a NUL

	if ( add_NUL )
		++n;

	u_char* b = new u_char[n];
	int i;
	for ( i = 0; i < int(s->size()); ++i )
		b[i] = (*s)[i];

	if ( add_NUL )
		b[i] = '\0';

	return new BroString(1, b, n - 1);
	}

BroString* SMB_Session::ExtractString(binpac::SMB::SMB_unicode_string const* s)
	{
	bool add_NUL = true;
	int n = s->s()->size();

	if ( n > 0 && ((*s->s())[n - 1] & 0xff) == '\0' )
		add_NUL = false;	// already has a NUL

	if ( add_NUL )
		++n;

	u_char* b = new u_char[n];

	int i;
	for ( i = 0; i < int(s->s()->size()); ++i )
		{
		uint16 x = (*s->s())[i];
		if ( x & 0xff00 )
			Weird(fmt("unicode string confusion: 0x%04x", x));

		b[i] = u_char(x & 0xff);
		}

	if ( add_NUL )
		b[i] = '\0';

	return new BroString(1, b, n - 1);
	}

Val* SMB_Session::BuildHeaderVal(binpac::SMB::SMB_header const& hdr)
	{
	RecordVal* r = new RecordVal(smb_hdr);

	unsigned int status = 0;

	try
		{
		// FIXME: does this work?  We need to catch exceptions :-(
		// or use guard functions.
		status = hdr.status()->status() ||
			    hdr.status()->dos_error()->error_class() << 24 ||
			    hdr.status()->dos_error()->error();
		}
	catch ( const binpac::Exception& )
		{ // do nothing
		}

	r->Assign(0, new Val(hdr.command(), TYPE_COUNT));
	r->Assign(1, new Val(status, TYPE_COUNT));
	r->Assign(2, new Val(hdr.flags(), TYPE_COUNT));
	r->Assign(3, new Val(hdr.flags2(), TYPE_COUNT));
	r->Assign(4, new Val(hdr.tid(), TYPE_COUNT));
	r->Assign(5, new Val(hdr.pid(), TYPE_COUNT));
	r->Assign(6, new Val(hdr.uid(), TYPE_COUNT));
	r->Assign(7, new Val(hdr.mid(), TYPE_COUNT));

	return r;
	}

Val* SMB_Session::BuildTransactionVal(binpac::SMB::SMB_transaction const& trans)
	{
	RecordVal* r = new RecordVal(smb_trans);

	// r->Assign(0, new Val(variable, type));

	return r;
	}

Val* SMB_Session::BuildTransactionVal(binpac::SMB::SMB_transaction_secondary const& trans)
	{
	RecordVal* r = new RecordVal(smb_trans);

	// r->Assign(0, new Val(variable, type));

	return r;
	}

Val* SMB_Session::BuildTransactionVal(binpac::SMB::SMB_transaction_response const& trans)
	{
	RecordVal* r = new RecordVal(smb_trans);

	// r->Assign(0, new Val(variable, type));

	return r;
	}

Val* SMB_Session::BuildTransactionDataVal(binpac::SMB::SMB_transaction_data *data)
	{
	RecordVal* r = new RecordVal(smb_trans_data);

	// r->Assign(0, new Val(variable, type));

	return r;
	}

bool SMB_Session::LooksLikeRPC(int len, const u_char* msg)
	{
	try
		{
		binpac::DCE_RPC_Simple::DCE_RPC_Header h;
		h.Parse(msg, msg + len);

		if ( h.rpc_vers() == 5 && h.rpc_vers_minor() == 0 )
			{
			unsigned short frag_len = h.frag_length();
			if ( frag_len == len ||
			     BYTEORDER_SWAP16(frag_len) == len )
				{
				if ( ! is_IPC && DEBUG_smb_ipc )
					analyzer->Weird("TreeConnect to IPC missing");
				return true;
				}
			else
				{
				analyzer->Weird(fmt("endianness %d", h.byteorder()));
				analyzer->Weird(fmt("length mismatch: %d != %d",
					h.frag_length(), len));
				return false;
				}
			}
		}
	catch ( const binpac::Exception& )
		{ // do nothing
		}

	return false;
	}

bool SMB_Session::CheckRPC(int is_orig, int data_count, const u_char *data)
	{
	if ( LooksLikeRPC(data_count, data) )
		{
		if ( ! dce_rpc_session )
			dce_rpc_session = new dce_rpc::DCE_RPC_Session(analyzer);

		dce_rpc_session->DeliverPDU(is_orig, data_count, data);

		return true;
		}

	return false;
	}

Contents_SMB::Contents_SMB(Connection* conn, bool orig, SMB_Session* s)
: tcp::TCP_SupportAnalyzer("CONTENTS_SMB", conn, orig)
	{
	smb_session = s;
	msg_buf = 0;
	msg_len = 0;
	buf_len = 0;
	buf_n = 0;
	}

void Contents_SMB::InitMsgBuf()
	{
	delete [] msg_buf;
	msg_buf = new u_char[msg_len];
	buf_len = msg_len;
	buf_n = 0;
	}

Contents_SMB::~Contents_SMB()
	{
	delete [] msg_buf;
	}

void Contents_SMB::DeliverSMB(int len, const u_char* data)
	{
	// Check the 4-byte header.
	if ( strncmp((const char*) data, "\xffSMB", 4) )
		{
		Conn()->Weird(fmt("SMB-over-TCP header error: %02x%02x%02x%02x, \\x%02x%c%c%c",
			dshdr[0], dshdr[1], dshdr[2], dshdr[3],
			data[0], data[1], data[2], data[3]));
		SetSkip(1);
		}
	else
		smb_session->Deliver(IsOrig(), len, data);

	buf_n = 0;
	msg_len = 0;
	}

void Contents_SMB::DeliverStream(int len, const u_char* data, bool orig)
	{
	tcp::TCP_SupportAnalyzer::DeliverStream(len, data, orig);

	while ( len > 0 )
		{
		if ( ! msg_len )
			{
			// Get the SMB-over-TCP header (4 bytes).
			while ( buf_n < 4 && len > 0 )
				{
				dshdr[buf_n] = *data;
				++buf_n; ++data; --len;
				}

			if ( buf_n < 4 )
				return;

			buf_n = 0;
			for ( int i = 1; i < 4; ++i )
				msg_len = ( msg_len << 8 ) + dshdr[i];

			if ( dshdr[0] != 0 )
				{
				// Netbios header indicates this is NOT
				// a session message ...
				//	0x81 = session request
				//	0x82 = positive response
				//	0x83 = neg response
				//	0x84 = retarget(?)
				//	0x85 = keepalive
				// Maybe we should just generate a Netbios
				// event and die?
				Conn()->Weird("SMB checked Netbios type and found != 0");
				SetSkip(1);
				return;
				}

			else if ( msg_len <= 4 )
				{
				Conn()->Weird("SMB message length error");
				SetSkip(1);
				return;
				}
			}

		if ( buf_n == 0 && msg_len <= len )
			{
			// The fast lane:
			// Keep msg_len -- it will be changed in DeliverSMB
			int mlen = msg_len;
			DeliverSMB(msg_len, data);
			len -= mlen;
			data += mlen;
			}

		else
			{
			if ( buf_len < msg_len )
				InitMsgBuf();

			while ( buf_n < msg_len && len > 0 )
				{
				msg_buf[buf_n] = *data;
				++buf_n;
				++data;
				--len;
				}

			if ( buf_n < msg_len )
				return;

			DeliverSMB(msg_len, msg_buf);
			}
		}
	}

SMB_Analyzer::SMB_Analyzer(Connection* conn)
: tcp::TCP_ApplicationAnalyzer("SMB", conn)
	{
	smb_session = new SMB_Session(this);
	o_smb = new Contents_SMB(conn, true, smb_session);
	r_smb = new Contents_SMB(conn, false, smb_session);
	AddSupportAnalyzer(o_smb);
	AddSupportAnalyzer(r_smb);
	}

SMB_Analyzer::~SMB_Analyzer()
	{
	delete smb_session;
	}
