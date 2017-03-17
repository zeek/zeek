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
X509 *helper_sk_X509_value(STACK_OF(X509) *certs, int i)
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

static void OCSP_RESPID_bio(OCSP_RESPID *resp_id, BIO* bio)
	{
	if (resp_id->type == V_OCSP_RESPID_NAME)
		X509_NAME_print_ex(bio, resp_id->value.byName, 0, XN_FLAG_ONELINE);
	else if (resp_id->type == V_OCSP_RESPID_KEY)
		i2a_ASN1_STRING(bio, resp_id->value.byKey, V_ASN1_OCTET_STRING);
	}

void ocsp_add_cert_id(OCSP_CERTID *cert_id, val_list* vl, BIO* bio)
	{
	char buf[OCSP_STRING_BUF_SIZE];
	memset(buf, 0, sizeof(buf));

	i2a_ASN1_OBJECT(bio, cert_id->hashAlgorithm->algorithm);
	int len = BIO_read(bio, buf, sizeof(buf));
	vl->append(new StringVal(len, buf));
	BIO_reset(bio);

	i2a_ASN1_STRING(bio, cert_id->issuerNameHash, V_ASN1_OCTET_STRING);
	len = BIO_read(bio, buf, sizeof(buf));
	vl->append(new StringVal(len, buf));
	BIO_reset(bio);

	i2a_ASN1_STRING(bio, cert_id->issuerKeyHash, V_ASN1_OCTET_STRING);
	len = BIO_read(bio, buf, sizeof(buf));
	vl->append(new StringVal(len, buf));
	BIO_reset(bio);

	i2a_ASN1_INTEGER(bio, cert_id->serialNumber);
	vl->append(new StringVal(len, buf));
	BIO_reset(bio);
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

void file_analysis::OCSP::ParseRequest(OCSP_REQUEST *req, const char* fid)
	{
	OCSP_REQINFO *inf     = req->tbsRequest;

	char buf[OCSP_STRING_BUF_SIZE]; // we need a buffer for some of the openssl functions
	memset(buf, 0, sizeof(buf));

	// build up our response as we go along...
	val_list* vl = new val_list();
	vl->append(GetFile()->GetVal()->Ref());
	vl->append(new Val((uint64)ASN1_INTEGER_get(inf->version), TYPE_COUNT));
	BIO *bio = BIO_new(BIO_s_mem());

	if (inf->requestorName != NULL)
		{
		GENERAL_NAME_print(bio, inf->requestorName);
		int len = BIO_read(bio, buf, sizeof(buf));
		vl->append(new StringVal(len, buf));
		BIO_reset(bio);
		}
	else
		vl->append(new StringVal(0, ""));

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
	OCSP_RESPBYTES  *resp_bytes = resp->responseBytes;
	OCSP_BASICRESP  *basic_resp = nullptr;
	OCSP_RESPDATA   *resp_data  = nullptr;
	OCSP_RESPID     *resp_id    = nullptr;

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

	if (!resp_bytes)
		{
		Unref(status_val);
		return;
		}

	BIO *bio = BIO_new(BIO_s_mem());
	//i2a_ASN1_OBJECT(bio, resp_bytes->responseType);
	//int len = BIO_read(bio, buf, sizeof(buf));
	//BIO_reset(bio);

	// get the basic response
	basic_resp = OCSP_response_get1_basic(resp);
	if ( !basic_resp )
		goto clean_up;

	resp_data = basic_resp->tbsResponseData;
	if ( !resp_data )
		goto clean_up;

	vl = new val_list();
	vl->append(GetFile()->GetVal()->Ref());
	vl->append(resp_val->Ref());
	vl->append(status_val);
	vl->append(new Val((uint64)ASN1_INTEGER_get(resp_data->version), TYPE_COUNT));

	// responderID
	resp_id = resp_data->responderId;
	OCSP_RESPID_bio(resp_id, bio);
	len = BIO_read(bio, buf, sizeof(buf));
	vl->append(new StringVal(len, buf));
	BIO_reset(bio);

	// producedAt
	vl->append(new Val(GetTimeFromAsn1(resp_data->producedAt, fid, reporter), TYPE_TIME));

	// responses
	resp_count = sk_OCSP_SINGLERESP_num(resp_data->responses);
	for ( int i=0; i<resp_count; i++ )
		{
		OCSP_SINGLERESP *single_resp = sk_OCSP_SINGLERESP_value(resp_data->responses, i);
		if ( !single_resp )
			continue;

		val_list* rvl = new val_list();
		rvl->append(GetFile()->GetVal()->Ref());

		// cert id
		OCSP_CERTID *cert_id = single_resp->certId;
		ocsp_add_cert_id(cert_id, rvl, bio);
		BIO_reset(bio);

		// certStatus
		OCSP_CERTSTATUS *cert_status = single_resp->certStatus;
		const char* cert_status_str = OCSP_cert_status_str(cert_status->type);
		rvl->append(new StringVal(strlen(cert_status_str), cert_status_str));

		// revocation time and reason if revoked
		if ( cert_status->type == V_OCSP_CERTSTATUS_REVOKED )
			{
			OCSP_REVOKEDINFO *revoked_info = cert_status->value.revoked;
			rvl->append(new Val(GetTimeFromAsn1(revoked_info->revocationTime, fid, reporter), TYPE_TIME));

			if ( revoked_info->revocationReason )
				{
				const char* revoke_reason = OCSP_crl_reason_str(ASN1_ENUMERATED_get(revoked_info->revocationReason));
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

		rvl->append(new Val(GetTimeFromAsn1(single_resp->thisUpdate, fid, reporter), TYPE_TIME));
		if ( single_resp->nextUpdate )
			rvl->append(new Val(GetTimeFromAsn1(single_resp->nextUpdate, fid, reporter), TYPE_TIME));
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

	i2a_ASN1_OBJECT(bio, basic_resp->signatureAlgorithm->algorithm);
	len = BIO_read(bio, buf, sizeof(buf));
	vl->append(new StringVal(len, buf));
	BIO_reset(bio);

	//i2a_ASN1_OBJECT(bio, basic_resp->signature);
	//len = BIO_read(bio, buf, sizeof(buf));
	//ocsp_resp_record->Assign(7, new StringVal(len, buf));
	//BIO_reset(bio);

	certs_vector = new VectorVal(internal_type("x509_opaque_vector")->AsVectorType());
	vl->append(certs_vector);
	if ( basic_resp->certs )
		{
		int num_certs = sk_X509_num(basic_resp->certs);
		for ( int i=0; i<num_certs; i++ )
			{
			::X509 *this_cert = X509_dup(helper_sk_X509_value(basic_resp->certs, i));
			//::X509 *this_cert = X509_dup(sk_X509_value(basic_resp->certs, i));
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
	delete[] ocsp_resp_buf;
	if ( !ocsp_resp )
		return false;
	return true;
	}
