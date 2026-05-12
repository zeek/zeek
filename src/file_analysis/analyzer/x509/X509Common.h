// See the file "COPYING" in the main distribution directory for copyright.

// Common base class for the X509 and OCSP analyzer, which share a fair amount of
// code

#pragma once

#include "zeek/zeek-config.h"

#include <openssl/asn1.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>

#include "zeek/file_analysis/Analyzer.h"

namespace zeek {

class EventHandlerPtr;
class Reporter;
class StringVal;
template<class T>
class IntrusivePtr;
using StringValPtr = IntrusivePtr<StringVal>;

namespace file_analysis {

class File;

namespace detail {

static_assert(ZEEK_OPENSSL_VERSION_MAJOR == OPENSSL_VERSION_MAJOR,
              "OpenSSL major version mismatch: Zeek was configured with a different "
              "OpenSSL major version than the headers being compiled against.");

// X509_get_ext(), X509_EXTENSION_get_object() and related functions return const
// pointers in OpenSSL 4.0+, but non-const in earlier versions. This is awkward, as
// we have the signatures in some functions. We use type aliases in these cases now,
// and adjust them to be the same as the OpenSSL API. Not pretty, but I don't have a
// better idea.
#if ZEEK_OPENSSL_VERSION_MAJOR >= 4
using openssl_x509_ext_t = const X509_EXTENSION;
using openssl_asn1_obj_t = const ASN1_OBJECT;
#else
using openssl_x509_ext_t = X509_EXTENSION;
using openssl_asn1_obj_t = ASN1_OBJECT;
#endif

class X509Common : public file_analysis::Analyzer {
public:
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

    static double GetTimeFromAsn1(const ASN1_TIME* atime, file_analysis::File* f, Reporter* reporter);

protected:
    X509Common(const zeek::Tag& arg_tag, RecordValPtr arg_args, file_analysis::File* arg_file);

    void ParseExtension(openssl_x509_ext_t* ex, const EventHandlerPtr& h, bool global);
    void ParseSignedCertificateTimestamps(openssl_x509_ext_t* ext);
    virtual void ParseExtensionsSpecific(openssl_x509_ext_t* ex, bool, openssl_asn1_obj_t*, const char*) = 0;
};

} // namespace detail
} // namespace file_analysis
} // namespace zeek
