// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "OCSP.h"
#include "X509.h"
#include "Event.h"

#include "types.bif.h"
#include "ocsp_events.bif.h"

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

IMPLEMENT_SERIAL(OCSP_RESPVal, SER_OCSP_RESP_VAL);

#define OCSP_STRING_BUF_SIZE 2048

static Val* get_ocsp_type(RecordVal* args, const char* name)
	{
	Val* rval = args->Lookup(name);

	if ( ! rval )
		reporter->Error("File extraction analyzer missing arg field: %s", name);

	return rval;
	}

static bool OCSP_RESPID_bio(OCSP_BASICRESP* basic_resp, BIO* bio)
	{
#if ( OPENSSL_VERSION_NUMBER < 0x10100000L )
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

bool ocsp_add_cert_id(const OCSP_CERTID* cert_id, val_list* vl, BIO* bio)
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
		vl->append(new StringVal(""));
		vl->append(new StringVal(""));
		vl->append(new StringVal(""));
		vl->append(new StringVal(""));
		return false;
		}

	char buf[OCSP_STRING_BUF_SIZE];
	memset(buf, 0, sizeof(buf));

	i2a_ASN1_OBJECT(bio, hash_alg);
	int len = BIO_read(bio, buf, sizeof(buf));
	vl->append(new StringVal(len, buf));
	BIO_reset(bio);

	i2a_ASN1_STRING(bio, issuer_name_hash, V_ASN1_OCTET_STRING);
	len = BIO_read(bio, buf, sizeof(buf));
	vl->append(new StringVal(len, buf));
	BIO_reset(bio);

	i2a_ASN1_STRING(bio, issuer_key_hash, V_ASN1_OCTET_STRING);
	len = BIO_read(bio, buf, sizeof(buf));
	vl->append(new StringVal(len, buf));
	BIO_reset(bio);

	i2a_ASN1_INTEGER(bio, serial_number);
	len = BIO_read(bio, buf, sizeof(buf));
	vl->append(new StringVal(len, buf));
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

bool file_analysis::OCSP::DeliverStream(const u_char* data, uint64 len)
	{
	ocsp_data.append(reinterpret_cast<const char*>(data), len);
	return true;
	}

bool file_analysis::OCSP::Undelivered(uint64 offset, uint64 len)
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
			reporter->Weird(fmt("OPENSSL Could not parse OCSP request (fuid %s)", GetFile()->GetID().c_str()));
			return false;
			}

		ParseRequest(req, GetFile()->GetID().c_str());
		OCSP_REQUEST_free(req);
		}
	else
		{
		OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE(NULL, &ocsp_char, ocsp_data.size());

		if (!resp)
			{
			reporter->Weird(fmt("OPENSSL Could not parse OCSP response (fuid %s)", GetFile()->GetID().c_str()));
			return false;
			}

		OCSP_RESPVal* resp_val = new OCSP_RESPVal(resp); // resp_val takes ownership
		ParseResponse(resp_val, GetFile()->GetID().c_str());
		Unref(resp_val);
		}

	return true;
}

#if ( OPENSSL_VERSION_NUMBER >= 0x10100000L )
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
static StringVal* parse_basic_resp_sig_alg(OCSP_BASICRESP* basic_resp,
                                           BIO* bio, char* buf, size_t buf_len)
	{
	int der_basic_resp_len = 0;
	unsigned char* der_basic_resp_dat = nullptr;

	der_basic_resp_len = i2d_OCSP_BASICRESP(basic_resp, &der_basic_resp_dat);

	if ( der_basic_resp_len <= 0 )
		return new StringVal("");

	const unsigned char* const_der_basic_resp_dat = der_basic_resp_dat;

	auto bseq = d2i_ASN1_SEQUENCE_ANY(nullptr, &const_der_basic_resp_dat,
	                                  der_basic_resp_len);

	if ( ! bseq )
		{
		OPENSSL_free(der_basic_resp_dat);
		return new StringVal("");
		}

	if ( sk_ASN1_TYPE_num(bseq) < 3 )
		{
		sk_ASN1_TYPE_free(bseq);
		OPENSSL_free(der_basic_resp_dat);
		return new StringVal("");
		}

	auto constexpr sig_alg_idx = 1u;
	auto aseq_type = sk_ASN1_TYPE_value(bseq, sig_alg_idx);

	if ( ASN1_TYPE_get(aseq_type) != V_ASN1_SEQUENCE )
		{
		sk_ASN1_TYPE_free(bseq);
		OPENSSL_free(der_basic_resp_dat);
		return new StringVal("");
		}

	auto aseq_str = aseq_type->value.asn1_string;
	auto aseq_len = ASN1_STRING_length(aseq_str);
	auto aseq_dat = ASN1_STRING_get0_data(aseq_str);

	auto aseq = d2i_ASN1_SEQUENCE_ANY(nullptr, &aseq_dat, aseq_len);

	if ( ! aseq )
		{
		sk_ASN1_TYPE_free(bseq);
		OPENSSL_free(der_basic_resp_dat);
		return new StringVal("");
		}

	if ( sk_ASN1_TYPE_num(aseq) < 1 )
		{
		sk_ASN1_TYPE_free(aseq);
		sk_ASN1_TYPE_free(bseq);
		OPENSSL_free(der_basic_resp_dat);
		return new StringVal("");
		}

	auto constexpr alg_obj_idx = 0u;
	auto alg_obj_type = sk_ASN1_TYPE_value(aseq, alg_obj_idx);

	if ( ASN1_TYPE_get(alg_obj_type) != V_ASN1_OBJECT )
		{
		sk_ASN1_TYPE_free(aseq);
		sk_ASN1_TYPE_free(bseq);
		OPENSSL_free(der_basic_resp_dat);
		return new StringVal("");
		}

	auto alg_obj = alg_obj_type->value.object;
	i2a_ASN1_OBJECT(bio, alg_obj);
	auto alg_len = BIO_read(bio, buf, buf_len);
	auto rval = new StringVal(alg_len, buf);
	BIO_reset(bio);

	sk_ASN1_TYPE_free(aseq);
	sk_ASN1_TYPE_free(bseq);
	OPENSSL_free(der_basic_resp_dat);
	return rval;
	}

static Val* parse_basic_resp_data_version(OCSP_BASICRESP* basic_resp)
	{
	int der_basic_resp_len = 0;
	unsigned char* der_basic_resp_dat = nullptr;

	der_basic_resp_len = i2d_OCSP_BASICRESP(basic_resp, &der_basic_resp_dat);

	if ( der_basic_resp_len <= 0 )
		return new Val(-1, TYPE_COUNT);

	const unsigned char* const_der_basic_resp_dat = der_basic_resp_dat;

	auto bseq = d2i_ASN1_SEQUENCE_ANY(nullptr, &const_der_basic_resp_dat,
	                                  der_basic_resp_len);

	if ( ! bseq )
		{
		OPENSSL_free(der_basic_resp_dat);
		return new Val(-1, TYPE_COUNT);
		}

	if ( sk_ASN1_TYPE_num(bseq) < 3 )
		{
		sk_ASN1_TYPE_free(bseq);
		OPENSSL_free(der_basic_resp_dat);
		return new Val(-1, TYPE_COUNT);
		}

	auto constexpr resp_data_idx = 0u;
	auto dseq_type = sk_ASN1_TYPE_value(bseq, resp_data_idx);

	if ( ASN1_TYPE_get(dseq_type) != V_ASN1_SEQUENCE )
		{
		sk_ASN1_TYPE_free(bseq);
		OPENSSL_free(der_basic_resp_dat);
		return new Val(-1, TYPE_COUNT);
		}

	auto dseq_str = dseq_type->value.asn1_string;
	auto dseq_len = ASN1_STRING_length(dseq_str);
	auto dseq_dat = ASN1_STRING_get0_data(dseq_str);

	auto dseq = d2i_ASN1_SEQUENCE_ANY(nullptr, &dseq_dat, dseq_len);

	if ( ! dseq )
		{
		sk_ASN1_TYPE_free(bseq);
		OPENSSL_free(der_basic_resp_dat);
		return new StringVal("");
		}

	if ( sk_ASN1_TYPE_num(dseq) < 1 )
		{
		sk_ASN1_TYPE_free(dseq);
		sk_ASN1_TYPE_free(bseq);
		OPENSSL_free(der_basic_resp_dat);
		return new StringVal("");
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
		sk_ASN1_TYPE_free(dseq);
		sk_ASN1_TYPE_free(bseq);
		OPENSSL_free(der_basic_resp_dat);
		// Not present, use default value.
		return new Val(0, TYPE_COUNT);
		}

	uint64_t asn1_int = ASN1_INTEGER_get(version_type->value.integer);
	sk_ASN1_TYPE_free(dseq);
	sk_ASN1_TYPE_free(bseq);
	OPENSSL_free(der_basic_resp_dat);
	return new Val(asn1_int, TYPE_COUNT);
	}

static uint64 parse_request_version(OCSP_REQUEST* req)
	{
	int der_req_len = 0;
	unsigned char* der_req_dat = nullptr;
	der_req_len = i2d_OCSP_REQUEST(req, &der_req_dat);
	const unsigned char* const_der_req_dat = der_req_dat;

	if ( ! der_req_dat )
		return -1;

	auto rseq = d2i_ASN1_SEQUENCE_ANY(nullptr, &const_der_req_dat,
	                                  der_req_len);

	if ( ! rseq )
		{
		OPENSSL_free(der_req_dat);
		return -1;
		}

	if ( sk_ASN1_TYPE_num(rseq) < 1 )
		{
		sk_ASN1_TYPE_free(rseq);
		OPENSSL_free(der_req_dat);
		return -1;
		}

	auto constexpr version_idx = 0u;
	auto version_type = sk_ASN1_TYPE_value(rseq, version_idx);

	if ( ASN1_TYPE_get(version_type) != V_ASN1_INTEGER )
		{
		sk_ASN1_TYPE_free(rseq);
		OPENSSL_free(der_req_dat);
		// Not present, use default value.
		return 0;
		}

	uint64_t asn1_int = ASN1_INTEGER_get(version_type->value.integer);
	sk_ASN1_TYPE_free(rseq);
	OPENSSL_free(der_req_dat);
	return asn1_int;
	}
#endif

void file_analysis::OCSP::ParseRequest(OCSP_REQUEST* req, const char* fid)
	{
	char buf[OCSP_STRING_BUF_SIZE]; // we need a buffer for some of the openssl functions
	memset(buf, 0, sizeof(buf));

	// build up our response as we go along...
	val_list* vl = new val_list();
	vl->append(GetFile()->GetVal()->Ref());

	uint64 version = 0;

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L )
	if ( req->tbsRequest->version )
		version = (uint64)ASN1_INTEGER_get(req->tbsRequest->version);
#else
	version = parse_request_version(req);
	// TODO: try to parse out general name ?
#endif

	vl->append(new Val(version, TYPE_COUNT));

	BIO *bio = BIO_new(BIO_s_mem());

	mgr.QueueEvent(ocsp_request, vl);

	int req_count = OCSP_request_onereq_count(req);
	for ( int i=0; i<req_count; i++ )
		{
		val_list* rvl = new val_list();
		rvl->append(GetFile()->GetVal()->Ref());

		OCSP_ONEREQ *one_req = OCSP_request_onereq_get0(req, i);
		OCSP_CERTID *cert_id = OCSP_onereq_get0_id(one_req);

		ocsp_add_cert_id(cert_id, rvl, bio);
		mgr.QueueEvent(ocsp_request_certificate, rvl);
		}

	BIO_free(bio);
}

void file_analysis::OCSP::ParseResponse(OCSP_RESPVal *resp_val, const char* fid)
	{
	OCSP_RESPONSE   *resp       = resp_val->GetResp();
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

	val_list* vl = new val_list();
	vl->append(GetFile()->GetVal()->Ref());

	const char *status_str = OCSP_response_status_str(OCSP_response_status(resp));
	StringVal* status_val = new StringVal(strlen(status_str), status_str);
	vl->append(status_val->Ref());
	mgr.QueueEvent(ocsp_response_status, vl);
	vl = nullptr;

	//if (!resp_bytes)
	//	{
	//	Unref(status_val);
	//	return;
	//	}

	BIO *bio = BIO_new(BIO_s_mem());
	//i2a_ASN1_OBJECT(bio, resp_bytes->responseType);
	//int len = BIO_read(bio, buf, sizeof(buf));
	//BIO_reset(bio);

	// get the basic response
	basic_resp = OCSP_response_get1_basic(resp);
	if ( !basic_resp )
		goto clean_up;

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L )
	resp_data = basic_resp->tbsResponseData;
	if ( !resp_data )
		goto clean_up;
#endif

	vl = new val_list();
	vl->append(GetFile()->GetVal()->Ref());
	vl->append(resp_val->Ref());
	vl->append(status_val);

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L )
	vl->append(new Val((uint64)ASN1_INTEGER_get(resp_data->version), TYPE_COUNT));
#else
	vl->append(parse_basic_resp_data_version(basic_resp));
#endif

	// responderID
	if ( OCSP_RESPID_bio(basic_resp, bio) )
		{
		len = BIO_read(bio, buf, sizeof(buf));
		vl->append(new StringVal(len, buf));
		BIO_reset(bio);
		}
	else
		{
		reporter->Weird("OpenSSL failed to get OCSP responder id");
		vl->append(new StringVal(""));
		}

	// producedAt
#if ( OPENSSL_VERSION_NUMBER < 0x10100000L )
	produced_at = resp_data->producedAt;
#else
	produced_at = OCSP_resp_get0_produced_at(basic_resp);
#endif

	vl->append(new Val(GetTimeFromAsn1(produced_at, fid, reporter), TYPE_TIME));

	// responses

	resp_count = OCSP_resp_count(basic_resp);

	for ( int i=0; i<resp_count; i++ )
		{
		OCSP_SINGLERESP* single_resp = OCSP_resp_get0(basic_resp, i);

		if ( !single_resp )
			continue;

		val_list* rvl = new val_list();
		rvl->append(GetFile()->GetVal()->Ref());

		// cert id
		const OCSP_CERTID* cert_id = nullptr;

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L )
		cert_id = single_resp->certId;
#else
		cert_id = OCSP_SINGLERESP_get0_id(single_resp);
#endif

		ocsp_add_cert_id(cert_id, rvl, bio);
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
		rvl->append(new StringVal(strlen(cert_status_str), cert_status_str));

		// revocation time and reason if revoked
		if ( status == V_OCSP_CERTSTATUS_REVOKED )
			{
			rvl->append(new Val(GetTimeFromAsn1(revoke_time, fid, reporter), TYPE_TIME));

			if ( reason != OCSP_REVOKED_STATUS_NOSTATUS )
				{
				const char* revoke_reason = OCSP_crl_reason_str(reason);
				rvl->append(new StringVal(strlen(revoke_reason), revoke_reason));
				}
			else
				rvl->append(new StringVal(0, ""));
			}
		else
			{
			rvl->append(new Val(0, TYPE_TIME));
			rvl->append(new StringVal(0, ""));
			}

		if ( this_update )
			rvl->append(new Val(GetTimeFromAsn1(this_update, fid, reporter), TYPE_TIME));
		else
			rvl->append(new Val(0, TYPE_TIME));

		if ( next_update )
			rvl->append(new Val(GetTimeFromAsn1(next_update, fid, reporter), TYPE_TIME));
		else
			rvl->append(new Val(0, TYPE_TIME));

		mgr.QueueEvent(ocsp_response_certificate, rvl);

		num_ext = OCSP_SINGLERESP_get_ext_count(single_resp);
		for ( int k = 0; k < num_ext; ++k )
			{
			X509_EXTENSION* ex = OCSP_SINGLERESP_get_ext(single_resp, k);
			if ( ! ex )
				continue;

			ParseExtension(ex, ocsp_extension, false);
			}
		}

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L )
	i2a_ASN1_OBJECT(bio, basic_resp->signatureAlgorithm->algorithm);
	len = BIO_read(bio, buf, sizeof(buf));
	vl->append(new StringVal(len, buf));
	BIO_reset(bio);
#else
	vl->append(parse_basic_resp_sig_alg(basic_resp, bio, buf, sizeof(buf)));
#endif

	//i2a_ASN1_OBJECT(bio, basic_resp->signature);
	//len = BIO_read(bio, buf, sizeof(buf));
	//ocsp_resp_record->Assign(7, new StringVal(len, buf));
	//BIO_reset(bio);

	certs_vector = new VectorVal(internal_type("x509_opaque_vector")->AsVectorType());
	vl->append(certs_vector);

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L )
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
				certs_vector->Assign(i, new file_analysis::X509Val(this_cert));
			else
				reporter->Weird("OpenSSL returned null certificate");
			}
	  }
	mgr.QueueEvent(ocsp_response_bytes, vl);

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

OCSP_RESPVal::OCSP_RESPVal(OCSP_RESPONSE* arg_ocsp_resp) : OpaqueVal(ocsp_resp_opaque_type)
	{
	ocsp_resp = arg_ocsp_resp;
	}

OCSP_RESPVal::OCSP_RESPVal() : OpaqueVal(ocsp_resp_opaque_type)
	{
	ocsp_resp = nullptr;
	}

OCSP_RESPVal::~OCSP_RESPVal()
	{
	if (ocsp_resp)
		OCSP_RESPONSE_free(ocsp_resp);
	}

OCSP_RESPONSE* OCSP_RESPVal::GetResp() const
	{
	return ocsp_resp;
	}

bool OCSP_RESPVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_OCSP_RESP_VAL, OpaqueVal);
	unsigned char *buf = nullptr;
	int length = i2d_OCSP_RESPONSE(ocsp_resp, &buf);
	if ( length < 0 )
		return false;
	bool res = SERIALIZE_STR(reinterpret_cast<const char*>(buf), length);
	OPENSSL_free(buf);
	return res;
	}

bool OCSP_RESPVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(OpaqueVal)

	int length;
	unsigned char *ocsp_resp_buf, *opensslbuf;

	if ( ! UNSERIALIZE_STR(reinterpret_cast<char **>(&ocsp_resp_buf), &length) )
		return false;
	opensslbuf = ocsp_resp_buf; // OpenSSL likes to shift pointers around. really.
	ocsp_resp = d2i_OCSP_RESPONSE(nullptr, const_cast<const unsigned char**>(&opensslbuf), length);
	delete [] ocsp_resp_buf;
	if ( ! ocsp_resp )
		return false;
	return true;
	}
