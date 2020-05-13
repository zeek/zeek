// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "OCSP.h"
#include "X509.h"
#include "Event.h"
#include "Reporter.h"

#include "types.bif.h"
#include "ocsp_events.bif.h"

#include "file_analysis/File.h"
#include "file_analysis/Manager.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/opensslconf.h>

#include "file_analysis/analyzer/x509/X509.h"

// helper function of sk_X509_value to avoid namespace problem
// sk_X509_value(X,Y) = > SKM_sk_value(X509,X,Y)
// X509 => file_analysis::X509
X509* helper_sk_X509_value(const STACK_OF(X509)* certs, int i)
	{
	return sk_X509_value(certs, i);
	}

using namespace file_analysis;

#define OCSP_STRING_BUF_SIZE 2048

static IntrusivePtr<Val> get_ocsp_type(RecordVal* args, const char* name)
	{
	auto rval = args->Lookup(name);

	if ( ! rval )
		reporter->Error("File extraction analyzer missing arg field: %s", name);

	return rval;
	}

static bool OCSP_RESPID_bio(OCSP_BASICRESP* basic_resp, BIO* bio)
	{
#if ( OPENSSL_VERSION_NUMBER < 0x10100000L ) || defined(LIBRESSL_VERSION_NUMBER)
	ASN1_OCTET_STRING* key  = nullptr;
	X509_NAME*         name = nullptr;

	if ( ! basic_resp->tbsResponseData )
		return false;

	auto resp_id = basic_resp->tbsResponseData->responderId;

	if ( resp_id->type == V_OCSP_RESPID_NAME )
		name = resp_id->value.byName;
	else if ( resp_id->type == V_OCSP_RESPID_KEY )
		key = resp_id->value.byKey;
	else
		return false;
#else
	const ASN1_OCTET_STRING* key  = nullptr;
	const X509_NAME*         name = nullptr;

	if ( ! OCSP_resp_get0_id(basic_resp, &key, &name) )
		return false;
#endif

	if ( name )
		X509_NAME_print_ex(bio, name, 0, XN_FLAG_ONELINE);
	else
		i2a_ASN1_STRING(bio, key, V_ASN1_OCTET_STRING);

	return true;
	}

static bool ocsp_add_cert_id(const OCSP_CERTID* cert_id, zeek::Args* vl, BIO* bio)
	{
	ASN1_OBJECT*       hash_alg         = nullptr;
	ASN1_OCTET_STRING* issuer_name_hash = nullptr;
	ASN1_OCTET_STRING* issuer_key_hash  = nullptr;
	ASN1_INTEGER*      serial_number    = nullptr;

	auto res = OCSP_id_get0_info(&issuer_name_hash, &hash_alg,
	                             &issuer_key_hash, &serial_number,
	                             const_cast<OCSP_CERTID*>(cert_id));

	if ( ! res )
		{
		reporter->Weird("OpenSSL failed to get OCSP_CERTID info");
		vl->emplace_back(val_mgr->EmptyString());
		vl->emplace_back(val_mgr->EmptyString());
		vl->emplace_back(val_mgr->EmptyString());
		vl->emplace_back(val_mgr->EmptyString());
		return false;
		}

	char buf[OCSP_STRING_BUF_SIZE];
	memset(buf, 0, sizeof(buf));

	i2a_ASN1_OBJECT(bio, hash_alg);
	int len = BIO_read(bio, buf, sizeof(buf));
	vl->emplace_back(make_intrusive<StringVal>(len, buf));
	BIO_reset(bio);

	i2a_ASN1_STRING(bio, issuer_name_hash, V_ASN1_OCTET_STRING);
	len = BIO_read(bio, buf, sizeof(buf));
	vl->emplace_back(make_intrusive<StringVal>(len, buf));
	BIO_reset(bio);

	i2a_ASN1_STRING(bio, issuer_key_hash, V_ASN1_OCTET_STRING);
	len = BIO_read(bio, buf, sizeof(buf));
	vl->emplace_back(make_intrusive<StringVal>(len, buf));
	BIO_reset(bio);

	i2a_ASN1_INTEGER(bio, serial_number);
	len = BIO_read(bio, buf, sizeof(buf));
	vl->emplace_back(make_intrusive<StringVal>(len, buf));
	BIO_reset(bio);

	return true;
	}

file_analysis::Analyzer* OCSP::InstantiateRequest(RecordVal* args, File* file)
	{
	return new OCSP(args, file, true);
	}

file_analysis::Analyzer* OCSP::InstantiateReply(RecordVal* args, File* file)
	{
	return new OCSP(args, file, false);
	}

file_analysis::OCSP::OCSP(RecordVal* args, file_analysis::File* file, bool arg_request)
	: file_analysis::X509Common::X509Common(file_mgr->GetComponentTag("OCSP"), args, file), request(arg_request)
	{
	}

bool file_analysis::OCSP::DeliverStream(const u_char* data, uint64_t len)
	{
	ocsp_data.append(reinterpret_cast<const char*>(data), len);
	return true;
	}

bool file_analysis::OCSP::Undelivered(uint64_t offset, uint64_t len)
	{
	return false;
	}

// we parse the entire OCSP response in EOF, because we just pass it on
// to OpenSSL.
bool file_analysis::OCSP::EndOfFile()
	{
	const unsigned char* ocsp_char = reinterpret_cast<const unsigned char*>(ocsp_data.data());

	if ( request )
		{
		OCSP_REQUEST *req = d2i_OCSP_REQUEST(NULL, &ocsp_char, ocsp_data.size());

		if (!req)
			{
			reporter->Weird(GetFile(), "openssl_ocsp_request_parse_error");
			return false;
			}

		ParseRequest(req);
		OCSP_REQUEST_free(req);
		}
	else
		{
		OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE(NULL, &ocsp_char, ocsp_data.size());

		if (!resp)
			{
			reporter->Weird(GetFile(), "openssl_ocsp_response_parse_error");
			return false;
			}

		ParseResponse(resp);
		OCSP_RESPONSE_free(resp);
		}

	return true;
}

#if ( OPENSSL_VERSION_NUMBER >= 0x10100000L )

struct ASN1Seq {
	ASN1Seq(const unsigned char** der_in, long length)
		{ decoded = d2i_ASN1_SEQUENCE_ANY(nullptr, der_in, length); }

	~ASN1Seq()
		{ sk_ASN1_TYPE_pop_free(decoded, ASN1_TYPE_free); }

	explicit operator bool() const
		{ return decoded; }

	operator ASN1_SEQUENCE_ANY*() const
		{ return decoded; }

	ASN1_SEQUENCE_ANY* decoded;
};

// Re-encode and then parse out ASN1 structures to get at what we need...
/*-  BasicOCSPResponse       ::= SEQUENCE {
 *      tbsResponseData      ResponseData,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signature            BIT STRING,
 *      certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
typedef struct ocsp_basic_response_st {
    OCSP_RESPDATA *tbsResponseData;
    X509_ALGOR *signatureAlgorithm;
    ASN1_BIT_STRING *signature;
    STACK_OF(X509) *certs;
} OCSP_BASICRESP;
*/
static IntrusivePtr<StringVal> parse_basic_resp_sig_alg(OCSP_BASICRESP* basic_resp,
                                                        BIO* bio, char* buf,
                                                        size_t buf_len)
	{
	int der_basic_resp_len = 0;
	unsigned char* der_basic_resp_dat = nullptr;

	der_basic_resp_len = i2d_OCSP_BASICRESP(basic_resp, &der_basic_resp_dat);

	if ( der_basic_resp_len <= 0 )
		return val_mgr->EmptyString();

	const unsigned char* const_der_basic_resp_dat = der_basic_resp_dat;

	ASN1Seq bseq{&const_der_basic_resp_dat, der_basic_resp_len};

	if ( ! bseq )
		{
		OPENSSL_free(der_basic_resp_dat);
		return val_mgr->EmptyString();
		}

	if ( sk_ASN1_TYPE_num(bseq) < 3 )
		{
		OPENSSL_free(der_basic_resp_dat);
		return val_mgr->EmptyString();
		}

	auto constexpr sig_alg_idx = 1u;
	auto aseq_type = sk_ASN1_TYPE_value(bseq, sig_alg_idx);

	if ( ASN1_TYPE_get(aseq_type) != V_ASN1_SEQUENCE )
		{
		OPENSSL_free(der_basic_resp_dat);
		return val_mgr->EmptyString();
		}

	auto aseq_str = aseq_type->value.asn1_string;
	auto aseq_len = ASN1_STRING_length(aseq_str);
	auto aseq_dat = ASN1_STRING_get0_data(aseq_str);

	ASN1Seq aseq{&aseq_dat, aseq_len};

	if ( ! aseq )
		{
		OPENSSL_free(der_basic_resp_dat);
		return val_mgr->EmptyString();
		}

	if ( sk_ASN1_TYPE_num(aseq) < 1 )
		{
		OPENSSL_free(der_basic_resp_dat);
		return val_mgr->EmptyString();
		}

	auto constexpr alg_obj_idx = 0u;
	auto alg_obj_type = sk_ASN1_TYPE_value(aseq, alg_obj_idx);

	if ( ASN1_TYPE_get(alg_obj_type) != V_ASN1_OBJECT )
		{
		OPENSSL_free(der_basic_resp_dat);
		return val_mgr->EmptyString();
		}

	auto alg_obj = alg_obj_type->value.object;
	i2a_ASN1_OBJECT(bio, alg_obj);
	auto alg_len = BIO_read(bio, buf, buf_len);
	auto rval = make_intrusive<StringVal>(alg_len, buf);
	BIO_reset(bio);

	OPENSSL_free(der_basic_resp_dat);
	return rval;
	}

static IntrusivePtr<Val> parse_basic_resp_data_version(OCSP_BASICRESP* basic_resp)
	{
	int der_basic_resp_len = 0;
	unsigned char* der_basic_resp_dat = nullptr;

	der_basic_resp_len = i2d_OCSP_BASICRESP(basic_resp, &der_basic_resp_dat);

	if ( der_basic_resp_len <= 0 )
		return val_mgr->Count(-1);

	const unsigned char* const_der_basic_resp_dat = der_basic_resp_dat;

	ASN1Seq bseq{&const_der_basic_resp_dat, der_basic_resp_len};

	if ( ! bseq )
		{
		OPENSSL_free(der_basic_resp_dat);
		return val_mgr->Count(-1);
		}

	if ( sk_ASN1_TYPE_num(bseq) < 3 )
		{
		OPENSSL_free(der_basic_resp_dat);
		return val_mgr->Count(-1);
		}

	auto constexpr resp_data_idx = 0u;
	auto dseq_type = sk_ASN1_TYPE_value(bseq, resp_data_idx);

	if ( ASN1_TYPE_get(dseq_type) != V_ASN1_SEQUENCE )
		{
		OPENSSL_free(der_basic_resp_dat);
		return val_mgr->Count(-1);
		}

	auto dseq_str = dseq_type->value.asn1_string;
	auto dseq_len = ASN1_STRING_length(dseq_str);
	auto dseq_dat = ASN1_STRING_get0_data(dseq_str);

	ASN1Seq dseq{&dseq_dat, dseq_len};

	if ( ! dseq )
		{
		OPENSSL_free(der_basic_resp_dat);
		return val_mgr->Count(-1);
		}

	if ( sk_ASN1_TYPE_num(dseq) < 1 )
		{
		OPENSSL_free(der_basic_resp_dat);
		return val_mgr->Count(-1);
		}

/*-  ResponseData ::= SEQUENCE {
 *      version              [0] EXPLICIT Version DEFAULT v1,
 *      responderID              ResponderID,
 *      producedAt               GeneralizedTime,
 *      responses                SEQUENCE OF SingleResponse,
 *      responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
 */

	auto constexpr version_idx = 0u;
	auto version_type = sk_ASN1_TYPE_value(dseq, version_idx);

	if ( ASN1_TYPE_get(version_type) != V_ASN1_INTEGER )
		{
		OPENSSL_free(der_basic_resp_dat);
		// Not present, use default value.
		return val_mgr->Count(0);
		}

	uint64_t asn1_int = ASN1_INTEGER_get(version_type->value.integer);
	OPENSSL_free(der_basic_resp_dat);
	return val_mgr->Count(asn1_int);
	}

static uint64_t parse_request_version(OCSP_REQUEST* req)
	{
	int der_req_len = 0;
	unsigned char* der_req_dat = nullptr;
	der_req_len = i2d_OCSP_REQUEST(req, &der_req_dat);
	const unsigned char* const_der_req_dat = der_req_dat;

	if ( ! der_req_dat )
		return -1;

	ASN1Seq rseq{&const_der_req_dat, der_req_len};

	if ( ! rseq )
		{
		OPENSSL_free(der_req_dat);
		return -1;
		}

	if ( sk_ASN1_TYPE_num(rseq) < 1 )
		{
		OPENSSL_free(der_req_dat);
		return -1;
		}

	auto constexpr version_idx = 0u;
	auto version_type = sk_ASN1_TYPE_value(rseq, version_idx);

	if ( ASN1_TYPE_get(version_type) != V_ASN1_INTEGER )
		{
		OPENSSL_free(der_req_dat);
		// Not present, use default value.
		return 0;
		}

	uint64_t asn1_int = ASN1_INTEGER_get(version_type->value.integer);
	OPENSSL_free(der_req_dat);
	return asn1_int;
	}
#endif

void file_analysis::OCSP::ParseRequest(OCSP_REQUEST* req)
	{
	char buf[OCSP_STRING_BUF_SIZE]; // we need a buffer for some of the openssl functions
	memset(buf, 0, sizeof(buf));

	uint64_t version = 0;

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L ) || defined(LIBRESSL_VERSION_NUMBER)
	if ( req->tbsRequest->version )
		version = (uint64_t)ASN1_INTEGER_get(req->tbsRequest->version);
#else
	version = parse_request_version(req);
	// TODO: try to parse out general name ?
#endif

	if ( ocsp_request )
		mgr.Enqueue(ocsp_request,
			IntrusivePtr{NewRef{}, GetFile()->GetVal()},
			val_mgr->Count(version)
		);

	BIO *bio = BIO_new(BIO_s_mem());

	int req_count = OCSP_request_onereq_count(req);
	for ( int i=0; i<req_count; i++ )
		{
		zeek::Args rvl;
		rvl.reserve(5);
		rvl.emplace_back(NewRef{}, GetFile()->GetVal());

		OCSP_ONEREQ *one_req = OCSP_request_onereq_get0(req, i);
		OCSP_CERTID *cert_id = OCSP_onereq_get0_id(one_req);

		ocsp_add_cert_id(cert_id, &rvl, bio);

		if ( ocsp_request_certificate )
			mgr.Enqueue(ocsp_request_certificate, std::move(rvl));
		}

	BIO_free(bio);
}

void file_analysis::OCSP::ParseResponse(OCSP_RESPONSE *resp)
	{
	//OCSP_RESPBYTES  *resp_bytes = resp->responseBytes;
	OCSP_BASICRESP  *basic_resp = nullptr;
	OCSP_RESPDATA   *resp_data  = nullptr;
	OCSP_RESPID     *resp_id    = nullptr;
	const ASN1_GENERALIZEDTIME* produced_at = nullptr;
	const STACK_OF(X509)* certs = nullptr;

	int resp_count, num_ext = 0;
	VectorVal *certs_vector = nullptr;
	int len = 0;

 	char buf[OCSP_STRING_BUF_SIZE];
	memset(buf, 0, sizeof(buf));

	const char *status_str = OCSP_response_status_str(OCSP_response_status(resp));
	StringVal* status_val = new StringVal(strlen(status_str), status_str);

	if ( ocsp_response_status )
		mgr.Enqueue(ocsp_response_status,
			IntrusivePtr{NewRef{}, GetFile()->GetVal()},
			IntrusivePtr{NewRef{}, status_val}
		);

	//if (!resp_bytes)
	//	{
	//	Unref(status_val);
	//	return;
	//	}

	BIO *bio = BIO_new(BIO_s_mem());
	//i2a_ASN1_OBJECT(bio, resp_bytes->responseType);
	//int len = BIO_read(bio, buf, sizeof(buf));
	//BIO_reset(bio);

	zeek::Args vl;
	vl.reserve(8);

	// get the basic response
	basic_resp = OCSP_response_get1_basic(resp);
	if ( !basic_resp )
		{
		Unref(status_val);
		goto clean_up;
		}

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L ) || defined(LIBRESSL_VERSION_NUMBER)
	resp_data = basic_resp->tbsResponseData;
	if ( !resp_data )
		{
		Unref(status_val);
		goto clean_up;
		}
#endif

	vl.emplace_back(NewRef{}, GetFile()->GetVal());
	vl.emplace_back(AdoptRef{}, status_val);

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L ) || defined(LIBRESSL_VERSION_NUMBER)
	vl.emplace_back(val_mgr->Count((uint64_t)ASN1_INTEGER_get(resp_data->version)));
#else
	vl.emplace_back(parse_basic_resp_data_version(basic_resp));
#endif

	// responderID
	if ( OCSP_RESPID_bio(basic_resp, bio) )
		{
		len = BIO_read(bio, buf, sizeof(buf));
		vl.emplace_back(make_intrusive<StringVal>(len, buf));
		BIO_reset(bio);
		}
	else
		{
		reporter->Weird("OpenSSL failed to get OCSP responder id");
		vl.emplace_back(val_mgr->EmptyString());
		}

	// producedAt
#if ( OPENSSL_VERSION_NUMBER < 0x10100000L ) || defined(LIBRESSL_VERSION_NUMBER)
	produced_at = resp_data->producedAt;
#else
	produced_at = OCSP_resp_get0_produced_at(basic_resp);
#endif

	vl.emplace_back(make_intrusive<Val>(GetTimeFromAsn1(produced_at, GetFile(), reporter), TYPE_TIME));

	// responses

	resp_count = OCSP_resp_count(basic_resp);

	for ( int i=0; i<resp_count; i++ )
		{
		OCSP_SINGLERESP* single_resp = OCSP_resp_get0(basic_resp, i);

		if ( !single_resp )
			continue;

		zeek::Args rvl;
		rvl.reserve(10);
		rvl.emplace_back(NewRef{}, GetFile()->GetVal());

		// cert id
		const OCSP_CERTID* cert_id = nullptr;

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L ) || defined(LIBRESSL_VERSION_NUMBER)
		cert_id = single_resp->certId;
#else
		cert_id = OCSP_SINGLERESP_get0_id(single_resp);
#endif

		ocsp_add_cert_id(cert_id, &rvl, bio);
		BIO_reset(bio);

		// certStatus
		int status = V_OCSP_CERTSTATUS_UNKNOWN;
		int reason = OCSP_REVOKED_STATUS_NOSTATUS;
		ASN1_GENERALIZEDTIME* revoke_time = nullptr;
		ASN1_GENERALIZEDTIME* this_update = nullptr;
		ASN1_GENERALIZEDTIME* next_update = nullptr;

		if ( ! OCSP_resp_find_status(basic_resp,
		                             const_cast<OCSP_CERTID*>(cert_id),
		                             &status, &reason, &revoke_time,
		                             &this_update, &next_update) )
			reporter->Weird("OpenSSL failed to find status of OCSP response");

		const char* cert_status_str = OCSP_cert_status_str(status);
		rvl.emplace_back(make_intrusive<StringVal>(strlen(cert_status_str), cert_status_str));

		// revocation time and reason if revoked
		if ( status == V_OCSP_CERTSTATUS_REVOKED )
			{
			rvl.emplace_back(make_intrusive<Val>(GetTimeFromAsn1(revoke_time, GetFile(), reporter), TYPE_TIME));

			if ( reason != OCSP_REVOKED_STATUS_NOSTATUS )
				{
				const char* revoke_reason = OCSP_crl_reason_str(reason);
				rvl.emplace_back(make_intrusive<StringVal>(strlen(revoke_reason), revoke_reason));
				}
			else
				rvl.emplace_back(make_intrusive<StringVal>(0, ""));
			}
		else
			{
			rvl.emplace_back(make_intrusive<Val>(0.0, TYPE_TIME));
			rvl.emplace_back(make_intrusive<StringVal>(0, ""));
			}

		if ( this_update )
			rvl.emplace_back(make_intrusive<Val>(GetTimeFromAsn1(this_update, GetFile(), reporter), TYPE_TIME));
		else
			rvl.emplace_back(make_intrusive<Val>(0.0, TYPE_TIME));

		if ( next_update )
			rvl.emplace_back(make_intrusive<Val>(GetTimeFromAsn1(next_update, GetFile(), reporter), TYPE_TIME));
		else
			rvl.emplace_back(make_intrusive<Val>(0.0, TYPE_TIME));

		if ( ocsp_response_certificate )
			mgr.Enqueue(ocsp_response_certificate, std::move(rvl));

		num_ext = OCSP_SINGLERESP_get_ext_count(single_resp);
		for ( int k = 0; k < num_ext; ++k )
			{
			X509_EXTENSION* ex = OCSP_SINGLERESP_get_ext(single_resp, k);
			if ( ! ex )
				continue;

			ParseExtension(ex, ocsp_extension, false);
			}
		}

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L ) || defined(LIBRESSL_VERSION_NUMBER)
	i2a_ASN1_OBJECT(bio, basic_resp->signatureAlgorithm->algorithm);
	len = BIO_read(bio, buf, sizeof(buf));
	vl.emplace_back(make_intrusive<StringVal>(len, buf));
	BIO_reset(bio);
#else
	vl.emplace_back(parse_basic_resp_sig_alg(basic_resp, bio, buf, sizeof(buf)));
#endif

	//i2a_ASN1_OBJECT(bio, basic_resp->signature);
	//len = BIO_read(bio, buf, sizeof(buf));
	//ocsp_resp_record->Assign(7, make_intrusive<StringVal>(len, buf));
	//BIO_reset(bio);

	certs_vector = new VectorVal(zeek::id::lookup_type<VectorType>("x509_opaque_vector"));
	vl.emplace_back(AdoptRef{}, certs_vector);

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L ) || defined(LIBRESSL_VERSION_NUMBER)
	certs = basic_resp->certs;
#else
	certs = OCSP_resp_get0_certs(basic_resp);
#endif

	if ( certs )
		{
		int num_certs = sk_X509_num(certs);
		for ( int i=0; i<num_certs; i++ )
			{
			::X509 *this_cert = X509_dup(helper_sk_X509_value(certs, i));
			//::X509 *this_cert = X509_dup(sk_X509_value(certs, i));
			if (this_cert)
				certs_vector->Assign(i, make_intrusive<file_analysis::X509Val>(this_cert));
			else
				reporter->Weird("OpenSSL returned null certificate");
			}
	  }

	if ( ocsp_response_bytes )
		mgr.Enqueue(ocsp_response_bytes, std::move(vl));

	// ok, now that we are done with the actual certificate - let's parse extensions :)
	num_ext = OCSP_BASICRESP_get_ext_count(basic_resp);
	for ( int k = 0; k < num_ext; ++k )
		{
		X509_EXTENSION* ex = OCSP_BASICRESP_get_ext(basic_resp, k);
		if ( ! ex )
			continue;

		ParseExtension(ex, ocsp_extension, true);
		}

clean_up:
	if (basic_resp)
		OCSP_BASICRESP_free(basic_resp);
	BIO_free(bio);
}

void file_analysis::OCSP::ParseExtensionsSpecific(X509_EXTENSION* ex, bool global, ASN1_OBJECT* ext_asn, const char* oid)
	{
	// In OpenSSL 1.0.2+, we can get the extension by using NID_ct_cert_scts.
	// In OpenSSL <= 1.0.1, this is not yet defined yet, so we have to manually
	// look it up by performing a string comparison on the oid.
#ifdef NID_ct_cert_scts
	if ( OBJ_obj2nid(ext_asn) == NID_ct_cert_scts )
#else
	if ( strcmp(oid, "1.3.6.1.4.1.11129.2.4.5") == 0 )
#endif
		ParseSignedCertificateTimestamps(ex);
	}

