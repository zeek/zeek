// See the file "COPYING" in the main distribution directory for copyright.

// Common base class for the X509 and OCSP analyzer, which share a fair amount of
// code

#pragma once

#include "file_analysis/Analyzer.h"

#include <openssl/x509.h>
#include <openssl/asn1.h>

ZEEK_FORWARD_DECLARE_NAMESPACED(EventHandlerPtr, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Reporter, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(StringVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(File, zeek, file_analysis);
ZEEK_FORWARD_DECLARE_NAMESPACED(Tag, zeek, file_analysis);

namespace zeek {
template <class T> class IntrusivePtr;
using StringValPtr = zeek::IntrusivePtr<StringVal>;
}

namespace zeek::file_analysis::detail {

class X509Common : public zeek::file_analysis::Analyzer {
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
	static zeek::StringValPtr GetExtensionFromBIO(BIO* bio, zeek::file_analysis::File* f = nullptr);

	static double GetTimeFromAsn1(const ASN1_TIME* atime, zeek::file_analysis::File* f,
	                              zeek::Reporter* reporter);

protected:
	X509Common(const zeek::file_analysis::Tag& arg_tag,
	           zeek::RecordValPtr arg_args,
	           zeek::file_analysis::File* arg_file);

	void ParseExtension(X509_EXTENSION* ex, const zeek::EventHandlerPtr& h, bool global);
	void ParseSignedCertificateTimestamps(X509_EXTENSION* ext);
	virtual void ParseExtensionsSpecific(X509_EXTENSION* ex, bool, ASN1_OBJECT*, const char*) = 0;
};

} // namespace zeek:file_analysis

namespace file_analysis {

	using X509Common [[deprecated("Remove in v4.1. Use zeek::file_analysis::detail::X509Common.")]] = zeek::file_analysis::detail::X509Common;

} // namespace file_analysis
