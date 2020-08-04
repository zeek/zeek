// See the file "COPYING" in the main distribution directory for copyright.

#include "KRB.h"

#include <unistd.h>

#include "types.bif.h"
#include "events.bif.h"

namespace zeek::analyzer::krb {

bool KRB_Analyzer::krb_available = false;
#ifdef USE_KRB5
krb5_context KRB_Analyzer::krb_context = nullptr;
krb5_keytab KRB_Analyzer::krb_keytab = nullptr;
std::once_flag KRB_Analyzer::krb_initialized;
#endif

KRB_Analyzer::KRB_Analyzer(zeek::Connection* conn)
	: Analyzer("KRB", conn)
	{
	interp = new binpac::KRB::KRB_Conn(this);
#ifdef USE_KRB5
	std::call_once(krb_initialized, Initialize_Krb);
#endif
	}

#ifdef USE_KRB5
static void warn_krb(const char* msg, krb5_context ctx, krb5_error_code code)
	{
	auto err = krb5_get_error_message(ctx, code);
	zeek::reporter->Warning("%s (%s)", msg, err);
	krb5_free_error_message(ctx, err);
	}

void KRB_Analyzer::Initialize_Krb()
	{
	if ( zeek::BifConst::KRB::keytab->Len() == 0 )
		return; // no keytab set

	const char* keytab_filename = zeek::BifConst::KRB::keytab->CheckString();
	if ( access(keytab_filename, R_OK) != 0 )
		{
		zeek::reporter->Warning("KRB: Can't access keytab (%s)", keytab_filename);
		return;
		}

	krb5_error_code retval = krb5_init_context(&krb_context);
	if ( retval )
		{
		warn_krb("KRB: Couldn't initialize the context", krb_context, retval);
		return;
		}

	retval = krb5_kt_resolve(krb_context, keytab_filename, &krb_keytab);
	if ( retval )
		{
		warn_krb("KRB: Couldn't resolve keytab", krb_context, retval);
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
				 uint64_t seq, const zeek::IP_Hdr* ip, int caplen)
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

zeek::StringValPtr KRB_Analyzer::GetAuthenticationInfo(const zeek::String* principal,
                                                       const zeek::String* ciphertext,
                                                       const bro_uint_t enctype)
	{
#ifdef USE_KRB5
	if ( !krb_available )
		return nullptr;

	zeek::String delim("/");
	int pos = principal->FindSubstring(&delim);
	if ( pos == -1 )
		{
		zeek::reporter->Warning("KRB: Couldn't parse principal (%s)", principal->CheckString());
		return nullptr;
		}
	std::unique_ptr<zeek::String> service = unique_ptr<zeek::String>(principal->GetSubstring(0, pos));
	std::unique_ptr<zeek::String> hostname = unique_ptr<zeek::String>(principal->GetSubstring(pos + 1, -1));
	if ( !service || !hostname )
		{
		zeek::reporter->Warning("KRB: Couldn't parse principal (%s)", principal->CheckString());
		return nullptr;
		}
	krb5_principal sprinc;
	krb5_error_code retval = krb5_sname_to_principal(krb_context, hostname->CheckString(), service->CheckString(), KRB5_NT_SRV_HST, &sprinc);
	if ( retval )
		{
		warn_krb("KRB: Couldn't generate principal name", krb_context, retval);
		return nullptr;
		}

	auto tkt = static_cast<krb5_ticket*>(safe_malloc(sizeof(krb5_ticket)));
	memset(tkt, 0, sizeof(krb5_ticket));

	tkt->server = sprinc;
	tkt->enc_part.enctype = enctype;

	auto ctd = static_cast<char*>(safe_malloc(ciphertext->Len()));
	memcpy(ctd, ciphertext->Bytes(), ciphertext->Len());
	tkt->enc_part.ciphertext.data = ctd;
	tkt->enc_part.ciphertext.length = ciphertext->Len();

	retval = krb5_server_decrypt_ticket_keytab(krb_context, krb_keytab, tkt);

	if ( retval )
		{
		krb5_free_ticket(krb_context, tkt);
		warn_krb("KRB: Couldn't decrypt ticket", krb_context, retval);
		return nullptr;
		}

	char* cp;
	retval = krb5_unparse_name(krb_context, tkt->enc_part2->client, &cp);

	if ( retval )
		{
		krb5_free_ticket(krb_context, tkt);
		warn_krb("KRB: Couldn't unparse name", krb_context, retval);
		return nullptr;
		}

	auto ret = zeek::make_intrusive<zeek::StringVal>(cp);

	krb5_free_unparsed_name(krb_context, cp);
	krb5_free_ticket(krb_context, tkt);

	return ret;
#else
	return nullptr;
#endif
	}

} // namespace zeek::analyzer::krb
