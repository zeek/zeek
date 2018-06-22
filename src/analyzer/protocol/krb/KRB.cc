// See the file "COPYING" in the main distribution directory for copyright.

#include "KRB.h"
#include "types.bif.h"
#include "events.bif.h"

using namespace analyzer::krb;

bool KRB_Analyzer::krb_available = false;
#ifdef USE_KRB5
krb5_context KRB_Analyzer::krb_context = nullptr;
krb5_keytab KRB_Analyzer::krb_keytab = nullptr;
std::once_flag KRB_Analyzer::krb_initialized;
#endif

KRB_Analyzer::KRB_Analyzer(Connection* conn)
	: Analyzer("KRB", conn)
	{
	interp = new binpac::KRB::KRB_Conn(this);
#ifdef USE_KRB5
	std::call_once(krb_initialized, Initialize_Krb);
#endif
	}

#ifdef USE_KRB5
void KRB_Analyzer::Initialize_Krb()
	{
	if ( BifConst::KRB::keytab->Len() == 0 )
		return; // no keytab set

	const char* keytab_filename = BifConst::KRB::keytab->CheckString();
	if ( access(keytab_filename, R_OK) != 0 )
		{
		reporter->Warning("KRB: Can't access keytab (%s)", keytab_filename);
		return;
		}

	krb5_error_code retval = krb5_init_context(&krb_context);
	if ( retval )
		{
		reporter->Warning("KRB: Couldn't initialize the context (%s)", krb5_get_error_message(krb_context, retval));
		return;
		}

	retval = krb5_kt_resolve(krb_context, keytab_filename, &krb_keytab);
	if ( retval )
		{
		reporter->Warning("KRB: Couldn't resolve keytab (%s)", krb5_get_error_message(krb_context, retval));
		return;
		}
	krb_available = true;
	}
#endif

KRB_Analyzer::~KRB_Analyzer()
	{
	delete interp;
	}

void KRB_Analyzer::Done()
	{
	Analyzer::Done();
	}

void KRB_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
				 uint64 seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

StringVal* KRB_Analyzer::GetAuthenticationInfo(const BroString* principal, const BroString* ciphertext, const bro_uint_t enctype)
	{
#ifdef USE_KRB5
	if ( !krb_available )
		return nullptr;

	BroString delim("/");
	int pos = principal->FindSubstring(&delim);
	if ( pos == -1 )
		{
		reporter->Warning("KRB: Couldn't parse principal (%s)", principal->CheckString());
		return nullptr;
		}
	std::unique_ptr<BroString> service = unique_ptr<BroString>(principal->GetSubstring(0, pos));
	std::unique_ptr<BroString> hostname = unique_ptr<BroString>(principal->GetSubstring(pos + 1, -1));
	if ( !service || !hostname )
		{
		reporter->Warning("KRB: Couldn't parse principal (%s)", principal->CheckString());
		return nullptr;
		}
	krb5_principal sprinc;
	krb5_error_code retval = krb5_sname_to_principal(krb_context, hostname->CheckString(), service->CheckString(), KRB5_NT_SRV_HST, &sprinc);
	if ( retval )
		{
		reporter->Warning("KRB: Couldn't generate principal name (%s)", krb5_get_error_message(krb_context, retval));
		return nullptr;
		}

	krb5_ticket tkt;
	tkt.server = sprinc;
	tkt.enc_part.enctype = enctype;
	tkt.enc_part.ciphertext.data = reinterpret_cast<char*>(ciphertext->Bytes());
	tkt.enc_part.ciphertext.length = ciphertext->Len();

	retval = krb5_server_decrypt_ticket_keytab(krb_context, krb_keytab, &tkt);
	if ( retval )
		{
		reporter->Warning("KRB: Couldn't decrypt ticket (%s)", krb5_get_error_message(krb_context, retval));
		return nullptr;
		}

	char* cp;
	retval = krb5_unparse_name(krb_context, tkt.enc_part2->client, &cp);
	if ( retval )
		{
		reporter->Warning("KRB: Couldn't unparse name (%s)", krb5_get_error_message(krb_context, retval));
		return nullptr;
		}
	StringVal* ret = new StringVal(cp);

	krb5_free_unparsed_name(krb_context, cp);

	return ret;
#else
	return nullptr;
#endif
	}
