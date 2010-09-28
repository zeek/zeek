// $Id: X509.h 3526 2006-09-12 07:32:21Z vern $

#ifndef X509_H
#define X509_H

#include <sys/types.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "SSLProxy.h"

class X509_Cert {
public:
	static X509_STORE* ctx;
	static X509_LOOKUP* lookup;
	static X509_STORE_CTX csc;
	static bool bInited;

	// Initializes the OpenSSL library, which is used for verify().
	static int init();

	// Wrapper for X.509 error event.
	static void sslCertificateError(Contents_SSL* e, int error_numbe);

	// Retrieves a DER-encoded X.509 certificate.  Returns 0 on failure.
	static int verify(Contents_SSL* e, const u_char* data, uint32 len);
	static int verifyChain(Contents_SSL* e, const u_char* data, uint32 len);

	// Wrapper for the ssl_certificate event.
	static void sslCertificateEvent(Contents_SSL* e, X509* pCert);
};

#endif
