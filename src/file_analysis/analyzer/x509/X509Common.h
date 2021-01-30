// See the file "COPYING" in the main distribution directory for copyright.

// Common base class for the X509 and OCSP analyzer, which share a fair amount of
// code

#pragma once

#include <openssl/x509.h>
#include <openssl/asn1.h>

#include "zeek/file_analysis/Analyzer.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(EventHandlerPtr, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Reporter, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(StringVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(File, zeek, file_analysis);
ZEEK_FORWARD_DECLARE_NAMESPACED(Tag, zeek, file_analysis);

namespace zeek {
template <class T> class IntrusivePtr;
using StringValPtr = IntrusivePtr<StringVal>;
}

namespace zeek::file_analysis::detail {

class X509Common : public file_analysis::Analyzer {
public:
	~X509Common() override {};

	/**
	 * Retrieve an X509 extension value from an OpenSSL BIO to which it was
	 * written.
	 *
	 * @param bio the OpenSSL BIO to read. It will be freed by the function,
	 * including when an error occurs.
	 *
	 * @param f an associated file, if any (used for error reporting).
	 *
	 * @return The X509 extension value.
	 */
	static StringValPtr GetExtensionFromBIO(BIO* bio, file_analysis::File* f = nullptr);

	static double GetTimeFromAsn1(const ASN1_TIME* atime, file_analysis::File* f,
	                              Reporter* reporter);

protected:
	X509Common(const file_analysis::Tag& arg_tag,
	           RecordValPtr arg_args,
	           file_analysis::File* arg_file);

	void ParseExtension(X509_EXTENSION* ex, const EventHandlerPtr& h, bool global);
	void ParseSignedCertificateTimestamps(X509_EXTENSION* ext);
	virtual void ParseExtensionsSpecific(X509_EXTENSION* ex, bool, ASN1_OBJECT*, const char*) = 0;
};

} // namespace zeek::file_analysis
