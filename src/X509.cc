// $Id: X509.cc 6724 2009-06-07 09:23:03Z vern $

#include <openssl/err.h>

#include "X509.h"
#include "config.h"

// ### NOTE: while d2i_X509 does not take a const u_char** pointer,
// here we assume d2i_X509 does not write to <data>, so it is safe to
// convert data to a non-const pointer.  Could some X509 guru verify
// this?

X509* d2i_X509_(X509** px, const u_char** in, int len)
	{
#ifdef OPENSSL_D2I_X509_USES_CONST_CHAR
	  return d2i_X509(px, in, len);
#else
	  return d2i_X509(px, (u_char**)in, len);
#endif
	}

X509_STORE* X509_Cert::ctx = 0;
X509_LOOKUP* X509_Cert::lookup = 0;
X509_STORE_CTX X509_Cert::csc;
bool X509_Cert::bInited = false;

// TODO: Check if Key < 768 Bits => Weakness!
// FIXME: Merge verify and verifyChain.

void X509_Cert::sslCertificateEvent(Contents_SSL* e, X509* pCert)
	{
	EventHandlerPtr event = ssl_certificate;
	if ( ! event )
		return;

	char tmp[256];
	RecordVal* pX509Cert = new RecordVal(x509_type);

	X509_NAME_oneline(X509_get_issuer_name(pCert), tmp, sizeof tmp);
	pX509Cert->Assign(0, new StringVal(tmp));
	X509_NAME_oneline(X509_get_subject_name(pCert), tmp, sizeof tmp);
	pX509Cert->Assign(1, new StringVal(tmp));
	pX509Cert->Assign(2, new AddrVal(e->Conn()->OrigAddr()));

	val_list* vl = new val_list;
	vl->append(e->BuildConnVal());
	vl->append(pX509Cert);
	vl->append(new Val(e->IsOrig(), TYPE_BOOL));

	e->Conn()->ConnectionEvent(event, e, vl);
	}

void X509_Cert::sslCertificateError(Contents_SSL* e, int error_numbe)
	{
	Val* err_str = new StringVal(X509_verify_cert_error_string(csc.error));
	val_list* vl = new val_list;

	vl->append(e->BuildConnVal());
	vl->append(new Val(csc.error, TYPE_INT));
	vl->append(err_str);

	e->Conn()->ConnectionEvent(ssl_X509_error, e, vl);
	}

int X509_Cert::init()
	{
#if 0
	OpenSSL_add_all_algorithms();
#endif

	ctx = X509_STORE_new();
	int flag = 0;
	int ret = 0;

	if ( x509_trusted_cert_path &&
	     x509_trusted_cert_path->AsString()->Len() > 0 )
		{ // add the path(s) for the local CA's certificates
		const BroString* pString = x509_trusted_cert_path->AsString();

		lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_hash_dir());
		if ( ! lookup )
			{
			fprintf(stderr, "X509_Cert::init(): initing lookup failed\n");
			flag = 1;
			}

		int i = X509_LOOKUP_add_dir(lookup,
				(const char*) pString->Bytes(),
				X509_FILETYPE_PEM);
		if ( ! i )
			{
			fprintf( stderr, "X509_Cert::init(): error adding lookup directory\n" );
			ret = 0;
			}
		}
	else
		{
		printf("X509: Using the default trusted cert path.\n");
		X509_STORE_set_default_paths(ctx);
		}

	// Add crl functionality - will only add if defined and
	// X509_STORE_add_lookup was successful.
	if ( ! flag && x509_crl_file && x509_crl_file->AsString()->Len() > 0 )
		{
		const BroString* rString = x509_crl_file->AsString();

		if ( X509_load_crl_file(lookup, (const char*) rString->Bytes(),
					X509_FILETYPE_PEM) != 1 )
			{
			fprintf(stderr, "X509_Cert::init(): error reading CRL file\n");
			ret = 1;
			}

#if 0
		// Note, openssl version must be > 0.9.7(a).
		X509_STORE_set_flags(ctx,
			X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
#endif
		}

	bInited = true;
	return ret;
	}

int X509_Cert::verify(Contents_SSL* e, const u_char* data, uint32 len)
	{
	if ( ! bInited )
		init();

	X509* pCert = d2i_X509_(NULL, &data, len);
	if ( ! pCert )
		{
		// 5 = X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY
		sslCertificateError(e, 5);
		return -1;
		}

	sslCertificateEvent(e, pCert);

	X509_STORE_CTX_init(&csc, ctx, pCert, 0);
	X509_STORE_CTX_set_time(&csc, 0, (time_t) network_time);
	int i = X509_verify_cert(&csc);
	X509_STORE_CTX_cleanup(&csc);
	int ret = 0;

	int ext = X509_get_ext_count(pCert);

	if ( ext > 0 )
		{
		TableVal* x509ex = new TableVal(x509_extension);
		val_list* vl = new val_list;
		char buf[256];

		for ( int k = 0; k < ext; ++k )
			{
			X509_EXTENSION* ex = X509_get_ext(pCert, k);
			ASN1_OBJECT* obj = X509_EXTENSION_get_object(ex);
			i2t_ASN1_OBJECT(buf, sizeof(buf), obj);

			Val* index = new Val(k+1, TYPE_COUNT);
			Val* value = new StringVal(strlen(buf), buf);
			x509ex->Assign(index, value);
			Unref(index);
			// later we can do critical extensions like:
			// X509_EXTENSION_get_critical(ex);
			}

		vl->append(e->BuildConnVal());
		vl->append(x509ex);
		e->Conn()->ConnectionEvent(process_X509_extensions, e, vl);
		}

	if ( ! i )
		{
		sslCertificateError(e, csc.error);
		ret = csc.error;
		}
	else
		ret = 0;

	delete pCert;
	return ret;
	}

int X509_Cert::verifyChain(Contents_SSL* e, const u_char* data, uint32 len)
	{
	if ( ! bInited )
		init();

	// Gets an ssl3x cert chain (could be one single cert, too,
	// but in chain format).

	// Init the stack.
	STACK_OF(X509)* untrustedCerts = sk_X509_new_null();
	if ( ! untrustedCerts )
		{
		// Internal error allocating stack of untrusted certs.
		// 11 = X509_V_ERR_OUT_OF_MEM
		sslCertificateError(e, 11);
		return -1;
		}

	// NOT AGAIN!!!
	// Extract certificates and put them into an OpenSSL Stack.
	uint tempLength = 0;
	int certCount = 0;
	X509* pCert = 0; // base cert, this one is to be verified

	while ( tempLength < len )
		{
		++certCount;
		uint32 certLength =
			uint32((data[tempLength + 0] << 16) |
			       data[tempLength + 1] << 8) |
			data[tempLength + 2];

		// Points to current cert.
		const u_char* pCurrentCert = &data[tempLength+3];

		X509* pTemp = d2i_X509_(0, &pCurrentCert, certLength);
		if ( ! pTemp )
			{ // error is somewhat of a misnomer
			// 5 = X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY
			sslCertificateError(e, 5);
			//FIXME: free ptrs
			return -1;
			}

		if ( certCount == 1 )
			// The first certificate goes directly into the ctx.
			pCert = pTemp;
		else
			// The remaining certificates (if any) are put into
			// the list of untrusted certificates
			sk_X509_push(untrustedCerts, pTemp);

		tempLength += certLength + 3;
		}

	sslCertificateEvent(e, pCert);

	X509_STORE_CTX_init(&csc, ctx, pCert, untrustedCerts);
	X509_STORE_CTX_set_time(&csc, 0, (time_t) network_time);
	int i = X509_verify_cert(&csc);
	X509_STORE_CTX_cleanup(&csc);
	//X509_STORE_CTX_free(&csc);
	int ret = 0;

	if ( ! i )
		{
		sslCertificateError(e, csc.error);
		ret = csc.error;
		}
	else
		ret = 0;

	delete pCert;
	// Free the stack, incuding. contents.

	// FIXME: could this break Bro's memory tracking?
	sk_X509_pop_free(untrustedCerts, X509_free);

	return ret;
	}
