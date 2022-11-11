// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/file_analysis/analyzer/x509/X509Common.h"

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/opensslconf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "zeek/Reporter.h"
#include "zeek/file_analysis/analyzer/x509/events.bif.h"
#include "zeek/file_analysis/analyzer/x509/ocsp_events.bif.h"
#include "zeek/file_analysis/analyzer/x509/types.bif.h"
#include "zeek/file_analysis/analyzer/x509/x509-extension_pac.h"

namespace zeek::file_analysis::detail
	{

X509Common::X509Common(const zeek::Tag& arg_tag, RecordValPtr arg_args,
                       file_analysis::File* arg_file)
	: file_analysis::Analyzer(arg_tag, std::move(arg_args), arg_file)
	{
	}

static void EmitWeird(const char* name, file_analysis::File* file, const char* addl = "")
	{
	if ( file )
		reporter->Weird(file, name, addl);
	else
		reporter->Weird(name);
	}

double X509Common::GetTimeFromAsn1(const ASN1_TIME* atime, file_analysis::File* f,
                                   Reporter* reporter)
	{
	time_t lResult = 0;

	char lBuffer[26];
	char* pBuffer = lBuffer;

	const char* pString = (const char*)atime->data;
	unsigned int remaining = atime->length;

	if ( atime->type == V_ASN1_UTCTIME )
		{
		if ( remaining < 11 || remaining > 17 )
			{
			EmitWeird("x509_utc_length", f);
			return 0;
			}

		if ( pString[remaining - 1] != 'Z' )
			{
			// not valid according to RFC 2459 4.1.2.5.1
			EmitWeird("x509_utc_format", f);
			return 0;
			}

		// year is first two digits in YY format. Buffer expects YYYY format.
		if ( pString[0] < '5' ) // RFC 2459 4.1.2.5.1
			{
			*(pBuffer++) = '2';
			*(pBuffer++) = '0';
			}
		else
			{
			*(pBuffer++) = '1';
			*(pBuffer++) = '9';
			}

		memcpy(pBuffer, pString, 10);
		pBuffer += 10;
		pString += 10;
		remaining -= 10;
		}
	else if ( atime->type == V_ASN1_GENERALIZEDTIME )
		{
		// generalized time. We apparently ignore the YYYYMMDDHH case
		// for now and assume we always have minutes and seconds.
		// This should be ok because it is specified as a requirement in RFC 2459 4.1.2.5.2

		if ( remaining < 12 || remaining > 23 )
			{
			EmitWeird("x509_gen_time_length", f);
			return 0;
			}

		memcpy(pBuffer, pString, 12);
		pBuffer += 12;
		pString += 12;
		remaining -= 12;
		}
	else
		{
		EmitWeird("x509_invalid_time_type", f);
		return 0;
		}

	if ( (remaining == 0) || (*pString == 'Z') || (*pString == '-') || (*pString == '+') )
		{
		*(pBuffer++) = '0';
		*(pBuffer++) = '0';
		}

	else if ( remaining >= 2 )
		{
		*(pBuffer++) = *(pString++);
		*(pBuffer++) = *(pString++);

		remaining -= 2;

		// Skip any fractional seconds...
		if ( (remaining > 0) && (*pString == '.') )
			{
			pString++;
			remaining--;

			while ( (remaining > 0) && (*pString >= '0') && (*pString <= '9') )
				{
				pString++;
				remaining--;
				}
			}
		}

	else
		{
		EmitWeird("x509_time_add_char", f);
		return 0;
		}

	*(pBuffer++) = 'Z';
	*(pBuffer++) = '\0';

	time_t lSecondsFromUTC;

	if ( remaining == 0 || *pString == 'Z' )
		lSecondsFromUTC = 0;
	else
		{
		if ( remaining < 5 )
			{
			EmitWeird("x509_time_offset_underflow", f);
			return 0;
			}

		if ( (*pString != '+') && (*pString != '-') )
			{
			EmitWeird("x509_time_offset_type", f);
			return 0;
			}

		lSecondsFromUTC = ((pString[1] - '0') * 10 + (pString[2] - '0')) * 60;
		lSecondsFromUTC += (pString[3] - '0') * 10 + (pString[4] - '0');

		if ( *pString == '-' )
			lSecondsFromUTC = -lSecondsFromUTC;
		}

	tm lTime;
	lTime.tm_sec = ((lBuffer[12] - '0') * 10) + (lBuffer[13] - '0');
	lTime.tm_min = ((lBuffer[10] - '0') * 10) + (lBuffer[11] - '0');
	lTime.tm_hour = ((lBuffer[8] - '0') * 10) + (lBuffer[9] - '0');
	lTime.tm_mday = ((lBuffer[6] - '0') * 10) + (lBuffer[7] - '0');
	lTime.tm_mon = (((lBuffer[4] - '0') * 10) + (lBuffer[5] - '0')) - 1;
	lTime.tm_year = (lBuffer[0] - '0') * 1000 + (lBuffer[1] - '0') * 100 +
	                ((lBuffer[2] - '0') * 10) + (lBuffer[3] - '0');

	if ( lTime.tm_year > 1900 )
		lTime.tm_year -= 1900;

	lTime.tm_wday = 0;
	lTime.tm_yday = 0;
	lTime.tm_isdst = 0; // No DST adjustment requested

	lResult = mktime(&lTime);

	if ( lResult )
		{
		if ( lTime.tm_isdst != 0 )
			lResult -= 3600; // mktime may adjust for DST  (OS dependent)

		lResult += lSecondsFromUTC;
		}

	else
		lResult = 0;

	return lResult;
	}

void X509Common::ParseSignedCertificateTimestamps(X509_EXTENSION* ext)
	{
	// Ok, signed certificate timestamps are a bit of an odd case out; we don't
	// want to use the (basically nonexistent) OpenSSL functionality to parse them.
	// Instead we have our own, self-written binpac parser to parse just them,
	// which we will initialize here and tear down immediately again.

	ASN1_OCTET_STRING* ext_val = X509_EXTENSION_get_data(ext);
	// the octet string of the extension contains the octet string which in turn
	// contains the SCT. Obviously.

	unsigned char* ext_val_copy = (unsigned char*)OPENSSL_malloc(ext_val->length);
	unsigned char* ext_val_second_pointer = ext_val_copy;
	memcpy(ext_val_copy, ext_val->data, ext_val->length);

	ASN1_OCTET_STRING* inner = d2i_ASN1_OCTET_STRING(NULL, (const unsigned char**)&ext_val_copy,
	                                                 ext_val->length);
	if ( ! inner )
		{
		reporter->Error(
			"X509::ParseSignedCertificateTimestamps could not parse inner octet string");
		return;
		}

	binpac::X509Extension::MockConnection* conn = new binpac::X509Extension::MockConnection(this);
	binpac::X509Extension::SignedCertTimestampExt* interp =
		new binpac::X509Extension::SignedCertTimestampExt(conn);

	try
		{
		interp->NewData(inner->data, inner->data + inner->length);
		}
	catch ( const binpac::Exception& e )
		{
		// throw a warning or sth
		reporter->Error("X509::ParseSignedCertificateTimestamps could not parse SCT");
		}

	ASN1_OCTET_STRING_free(inner);
	OPENSSL_free(ext_val_second_pointer);

	interp->FlowEOF();

	delete interp;
	delete conn;
	}

void X509Common::ParseExtension(X509_EXTENSION* ex, const EventHandlerPtr& h, bool global)
	{
	char name[256];
	char oid[256];

	ASN1_OBJECT* ext_asn = X509_EXTENSION_get_object(ex);
	const char* short_name = OBJ_nid2sn(OBJ_obj2nid(ext_asn));

	OBJ_obj2txt(name, 255, ext_asn, 0);
	OBJ_obj2txt(oid, 255, ext_asn, 1);

	int critical = 0;
	if ( X509_EXTENSION_get_critical(ex) != 0 )
		critical = 1;

	BIO* bio = BIO_new(BIO_s_mem());
	if ( ! X509V3_EXT_print(bio, ex, 0, 0) )
		{
		unsigned char* buf = nullptr;
		int len = i2d_ASN1_OCTET_STRING(X509_EXTENSION_get_data(ex), &buf);
		if ( len >= 0 )
			{
			BIO_write(bio, buf, len);
			OPENSSL_free(buf);
			}
		}

	auto ext_val = GetExtensionFromBIO(bio, GetFile());

	if ( ! h )
		{
		// let individual analyzers parse more.
		ParseExtensionsSpecific(ex, global, ext_asn, oid);
		return;
		}

	if ( ! ext_val )
		ext_val = make_intrusive<StringVal>(0, "");

	auto pX509Ext = make_intrusive<RecordVal>(BifType::Record::X509::Extension);
	pX509Ext->Assign(0, name);

	if ( short_name and strlen(short_name) > 0 )
		pX509Ext->Assign(1, short_name);

	pX509Ext->Assign(2, oid);
	pX509Ext->Assign(3, critical);
	pX509Ext->Assign(4, ext_val);

	// send off generic extension event
	//
	// and then look if we have a specialized event for the extension we just
	// parsed. And if we have it, we send the specialized event on top of the
	// generic event that we just had. I know, that is... kind of not nice,
	// but I am not sure if there is a better way to do it...

	if ( h == ocsp_extension )
		event_mgr.Enqueue(h, GetFile()->ToVal(), std::move(pX509Ext), val_mgr->Bool(global));
	else
		event_mgr.Enqueue(h, GetFile()->ToVal(), std::move(pX509Ext));

	// let individual analyzers parse more.
	ParseExtensionsSpecific(ex, global, ext_asn, oid);
	}

StringValPtr X509Common::GetExtensionFromBIO(BIO* bio, file_analysis::File* f)
	{
	BIO_flush(bio);
	ERR_clear_error();
	int length = BIO_pending(bio);

	if ( ERR_peek_error() != 0 )
		{
		char tmp[120];
		ERR_error_string_n(ERR_get_error(), tmp, sizeof(tmp));
		EmitWeird("x509_get_ext_from_bio", f, tmp);
		BIO_free_all(bio);
		return nullptr;
		}

	if ( length == 0 )
		{
		BIO_free_all(bio);
		return val_mgr->EmptyString();
		}

	char* buffer = (char*)malloc(length);

	if ( ! buffer )
		{
		// Just emit an error here and try to continue instead of aborting
		// because it's unclear the length value is very reliable.
		reporter->Error("X509::GetExtensionFromBIO malloc(%d) failed", length);
		BIO_free_all(bio);
		return nullptr;
		}

	BIO_read(bio, (void*)buffer, length);
	auto ext_val = make_intrusive<StringVal>(length, buffer);

	free(buffer);
	BIO_free_all(bio);

	return ext_val;
	}

	} // namespace zeek::file_analysis::detail
