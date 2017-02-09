// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "OCSP.h"
#include "Event.h"

#include "ocsp_events.bif.h"
#include "ocsp_types.bif.h"

#include "file_analysis/Manager.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/opensslconf.h>

#include "file_analysis/analyzer/x509/X509.h"
#include "Asn1Time.h"

// helper function of sk_X509_value to avoid namespace problem
// sk_X509_value(X,Y) = > SKM_sk_value(X509,X,Y)
// X509 => file_analysis::X509
X509 *helper_sk_X509_value(STACK_OF(X509) *certs, int i)
	{
	return sk_X509_value(certs, i);
	}

using namespace file_analysis;

IMPLEMENT_SERIAL(OCSP_REQVal, SER_OCSP_REQ_VAL);
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

static RecordVal* ocsp_fill_cert_id(OCSP_CERTID *cert_id, RecordType* type, BIO* bio)
	{
	RecordVal *d = new RecordVal(type);
	char buf[OCSP_STRING_BUF_SIZE];
	memset(buf, 0, sizeof(buf));

	i2a_ASN1_OBJECT(bio, cert_id->hashAlgorithm->algorithm);
	int len = BIO_read(bio, buf, sizeof(buf));
	d->Assign(0, new StringVal(len, buf));
	BIO_reset(bio);

	i2a_ASN1_STRING(bio, cert_id->issuerNameHash, V_ASN1_OCTET_STRING);
	len = BIO_read(bio, buf, sizeof(buf));
	d->Assign(1, new StringVal(len, buf));
	BIO_reset(bio);

	i2a_ASN1_STRING(bio, cert_id->issuerKeyHash, V_ASN1_OCTET_STRING);
	len = BIO_read(bio, buf, sizeof(buf));
	d->Assign(2, new StringVal(len, buf));
	BIO_reset(bio);

	i2a_ASN1_INTEGER(bio, cert_id->serialNumber);
	d->Assign(3, new StringVal(len, buf));
	BIO_reset(bio);

	return d;
	}

file_analysis::Analyzer* OCSP::Instantiate(RecordVal* args, File* file)
	{
	Val* ocsp_type = get_ocsp_type(args, "ocsp_type");

	if (! ocsp_type )
		return 0;

	return new OCSP(args, file, ocsp_type->AsString()->CheckString());
	}

file_analysis::OCSP::OCSP(RecordVal* args, file_analysis::File* file, const string& arg_ocsp_type)
	: file_analysis::Analyzer(file_mgr->GetComponentTag("OCSP"), args, file)
	{
	ocsp_type = arg_ocsp_type;
	ocsp_data.clear();
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

	if (ocsp_type == "request")
		{
		OCSP_REQUEST *req = d2i_OCSP_REQUEST(NULL, &ocsp_char, ocsp_data.size());

		if (!req)
			{
			reporter->Weird(fmt("OPENSSL Could not parse OCSP request (fuid %s)", GetFile()->GetID().c_str()));
			return false;
			}

		OCSP_REQVal* req_val = new OCSP_REQVal(req); // req_val takes ownership

		RecordVal* req_record = ParseRequest(req_val, GetFile()->GetID().c_str());

		// and send the record on to scriptland
		val_list* vl = new val_list();
		vl->append(GetFile()->GetVal()->Ref());
		vl->append(req_val);
		vl->append(req_record);
		mgr.QueueEvent(ocsp_request, vl);
		}
	else if (ocsp_type == "response")
		{
		OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE(NULL, &ocsp_char, ocsp_data.size());
		if (!resp)
			{
			reporter->Weird(fmt("OPENSSL Could not parse OCSP response (fuid %s)", GetFile()->GetID().c_str()));
			return false;
			}

		OCSP_RESPVal* resp_val = new OCSP_RESPVal(resp); // resp_val takes ownership
		RecordVal* resp_record = ParseResponse(resp_val, GetFile()->GetID().c_str());

		// and send the record on to scriptland
		val_list* vl = new val_list();
		vl->append(GetFile()->GetVal()->Ref());
		vl->append(resp_val);
		vl->append(resp_record);
		mgr.QueueEvent(ocsp_response, vl);
		}
	else
		{
	  reporter->Weird(fmt("the given argument of ocsp_type (%s) is not recognized", ocsp_type.c_str()));
		return false;
		}

	return true;
}

RecordVal *file_analysis::OCSP::ParseRequest(OCSP_REQVal *req_val, const char* fid)
	{
	OCSP_REQUEST *req     = req_val->GetReq();
	OCSP_REQINFO *inf     = req->tbsRequest;

	char buf[OCSP_STRING_BUF_SIZE]; // we need a buffer for some of the openssl functions
	memset(buf, 0, sizeof(buf));

	RecordVal* ocsp_req_record = new RecordVal(BifType::Record::OCSP::Request);

	ocsp_req_record->Assign(0, new Val((uint64)ASN1_INTEGER_get(inf->version), TYPE_COUNT));
	BIO *bio = BIO_new(BIO_s_mem());

	if (inf->requestorName != NULL)
		{
		GENERAL_NAME_print(bio, inf->requestorName);
		int len = BIO_read(bio, buf, sizeof(buf));
		ocsp_req_record->Assign(1, new StringVal(len, buf));
		BIO_reset(bio);
		}

	VectorVal* all_req_bro = new VectorVal(internal_type("ocsp_req_vec")->AsVectorType());
	ocsp_req_record->Assign(2, all_req_bro);

	int req_count = OCSP_request_onereq_count(req);
	for ( int i=0; i<req_count; i++ )
		{
		OCSP_ONEREQ *one_req = OCSP_request_onereq_get0(req, i);
		OCSP_CERTID *cert_id = OCSP_onereq_get0_id(one_req);

		RecordVal* one_req_bro = ocsp_fill_cert_id(cert_id, BifType::Record::OCSP::OneReq, bio);
		all_req_bro->Assign(i, one_req_bro);
		}

	BIO_free(bio);

	return ocsp_req_record;
}

RecordVal *file_analysis::OCSP::ParseResponse(OCSP_RESPVal *resp_val, const char* fid)
	{
	OCSP_RESPONSE   *resp       = resp_val->GetResp();
	OCSP_RESPBYTES  *resp_bytes = resp->responseBytes;
	OCSP_BASICRESP  *basic_resp = nullptr;
	OCSP_RESPDATA   *resp_data  = nullptr;
	OCSP_RESPID     *resp_id    = nullptr;

	int resp_count = 0;
	VectorVal *all_resp_bro = nullptr;

 	char buf[OCSP_STRING_BUF_SIZE];
	memset(buf, 0, sizeof(buf));

	RecordVal *ocsp_resp_record = new RecordVal(BifType::Record::OCSP::Response);

	const char *status_str = OCSP_response_status_str(OCSP_response_status(resp));
	ocsp_resp_record->Assign(0, new StringVal(strlen(status_str), status_str));

	if (!resp_bytes)
		return ocsp_resp_record;

	BIO *bio = BIO_new(BIO_s_mem());
	i2a_ASN1_OBJECT(bio, resp_bytes->responseType);
	int len = BIO_read(bio, buf, sizeof(buf));
	ocsp_resp_record->Assign(1, new StringVal(len, buf));
	BIO_reset(bio);

	// get the basic response
	basic_resp = OCSP_response_get1_basic(resp);
	if ( !basic_resp )
		goto clean_up;

	resp_data = basic_resp->tbsResponseData;
	if ( !resp_data )
		goto clean_up;

	ocsp_resp_record->Assign(2, new Val((uint64)ASN1_INTEGER_get(resp_data->version), TYPE_COUNT));
	// responderID
	resp_id = resp_data->responderId;
	OCSP_RESPID_bio(resp_id, bio);
	len = BIO_read(bio, buf, sizeof(buf));
	ocsp_resp_record->Assign(3, new StringVal(len, buf));
	BIO_reset(bio);

	// producedAt
	ocsp_resp_record->Assign(4, new Val(GetTimeFromAsn1(resp_data->producedAt, fid, reporter), TYPE_TIME));

	all_resp_bro = new VectorVal(internal_type("ocsp_resp_vec")->AsVectorType());
	ocsp_resp_record->Assign(5, all_resp_bro);

	// responses
	resp_count = sk_OCSP_SINGLERESP_num(resp_data->responses);
	for ( int i=0; i<resp_count; i++ )
		{
		OCSP_SINGLERESP *single_resp = sk_OCSP_SINGLERESP_value(resp_data->responses, i);
		if ( !single_resp )
			continue;

		// cert id
		OCSP_CERTID *cert_id = single_resp->certId;
		RecordVal *single_resp_bro = ocsp_fill_cert_id(cert_id, BifType::Record::OCSP::SingleResp, bio);
		BIO_reset(bio);

		// certStatus
		OCSP_CERTSTATUS *cert_status = single_resp->certStatus;
		const char* cert_status_str = OCSP_cert_status_str(cert_status->type);
		single_resp_bro->Assign(4, new StringVal(strlen(cert_status_str), cert_status_str));

		// revocation time and reason if revoked
		if ( cert_status->type == V_OCSP_CERTSTATUS_REVOKED )
			{
			OCSP_REVOKEDINFO *revoked_info = cert_status->value.revoked;
			single_resp_bro->Assign(5, new Val(GetTimeFromAsn1(revoked_info->revocationTime, fid, reporter), TYPE_TIME));

			if ( revoked_info->revocationReason )
				{
				const char* revoke_reason = OCSP_crl_reason_str(ASN1_ENUMERATED_get(revoked_info->revocationReason));
				single_resp_bro->Assign(6, new StringVal(strlen(revoke_reason), revoke_reason));
				}
			}

		single_resp_bro->Assign(7, new Val(GetTimeFromAsn1(single_resp->thisUpdate, fid, reporter), TYPE_TIME));
		if ( single_resp->nextUpdate )
			single_resp_bro->Assign(8, new Val(GetTimeFromAsn1(single_resp->nextUpdate, fid, reporter), TYPE_TIME));

		all_resp_bro->Assign(i, single_resp_bro);
		}

	i2a_ASN1_OBJECT(bio, basic_resp->signatureAlgorithm->algorithm);
	len = BIO_read(bio, buf, sizeof(buf));
	ocsp_resp_record->Assign(6, new StringVal(len, buf));
	BIO_reset(bio);

	//i2a_ASN1_OBJECT(bio, basic_resp->signature);
	//len = BIO_read(bio, buf, sizeof(buf));
	//ocsp_resp_record->Assign(7, new StringVal(len, buf));
	//BIO_reset(bio);

	//certs
	if ( basic_resp->certs )
		{
		VectorVal *certs_vector = new VectorVal(internal_type("x509_opaque_vector")->AsVectorType());
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
		ocsp_resp_record->Assign(7, certs_vector);
	  }

clean_up:
	if (basic_resp)
		OCSP_BASICRESP_free(basic_resp);
	BIO_free(bio);
	return ocsp_resp_record;
}

OCSP_REQVal::OCSP_REQVal(OCSP_REQUEST* arg_ocsp_req) : OpaqueVal(ocsp_req_opaque_type)
	{
	ocsp_req = arg_ocsp_req;
	}

OCSP_REQVal::OCSP_REQVal() : OpaqueVal(ocsp_req_opaque_type)
	{
	ocsp_req = nullptr;
	}

OCSP_REQVal::~OCSP_REQVal()
	{
	if (ocsp_req)
		OCSP_REQUEST_free(ocsp_req);
	}

OCSP_REQUEST* OCSP_REQVal::GetReq() const
	{
	return ocsp_req;
	}

bool OCSP_REQVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_OCSP_REQ_VAL, OpaqueVal);
	unsigned char *buf = nullptr;
	int length = i2d_OCSP_REQUEST(ocsp_req, &buf);
	if ( length < 0 )
		return false;
	bool res = SERIALIZE_STR(reinterpret_cast<const char*>(buf), length);
	OPENSSL_free(buf);
	return res;
	}

bool OCSP_REQVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(OpaqueVal)

	int length;
	unsigned char *ocsp_req_buf, *opensslbuf;

	if ( ! UNSERIALIZE_STR(reinterpret_cast<char **>(&ocsp_req_buf), &length) )
		return false;
	opensslbuf = ocsp_req_buf; // OpenSSL likes to shift pointers around. really.
	ocsp_req = d2i_OCSP_REQUEST(nullptr, const_cast<const unsigned char**>(&opensslbuf), length);
	delete[] ocsp_req_buf;
	if ( !ocsp_req )
		return false;
	return true;
	}


//OCSP_RESPVal
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
