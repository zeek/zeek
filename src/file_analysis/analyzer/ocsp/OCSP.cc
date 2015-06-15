// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "OCSP.h"
#include "Event.h"

#include "events.bif.h"
#include "types.bif.h"

#include "file_analysis/Manager.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/opensslconf.h>

using namespace file_analysis;

IMPLEMENT_SERIAL(OCSP_REQVal, SER_OCSP_REQ_VAL);
IMPLEMENT_SERIAL(OCSP_RESPVal, SER_OCSP_RESP_VAL);

#define OCSP_STRING_BUF_SIZE 2048

//this function is copied from src/file_analysis/analyzer/extract/Extract.cc
static Val* get_extract_field_val(RecordVal* args, const char* name)
	{
	Val* rval = args->Lookup(name);
	if ( ! rval )
		reporter->Error("File extraction analyzer missing arg field: %s", name);
	return rval;
	}

//convert different ANS1 type to c string
static int ANS1_to_cstr(char *buf, int buf_len, void *data, int type)
	{
	if (data == NULL || buf == NULL || buf_len <=0)
		return -1;
	int new_len = -1;
	BIO *bio = BIO_new(BIO_s_mem());
	memset(buf, 0, buf_len);
	
	if (type == V_ASN1_OCTET_STRING)
		{
		if (i2a_ASN1_STRING(bio, (ASN1_STRING *)data, V_ASN1_OCTET_STRING) <= 0)
			goto err;
		}
	else if (type == V_ASN1_BIT_STRING)
		{
		if (i2a_ASN1_STRING(bio, (ASN1_STRING *)data, V_ASN1_BIT_STRING) <= 0)
			goto err;
		}
	else if (type == V_ASN1_INTEGER)
		{
		if (i2a_ASN1_INTEGER(bio, (ASN1_INTEGER *)data) <= 0)
			goto err;
		}
	else if (type == V_ASN1_OBJECT)
		{
		if (i2a_ASN1_OBJECT(bio, (ASN1_OBJECT *)data) <= 0)
			goto err;
		}
	else if (type == V_ASN1_GENERALIZEDTIME)
		{
		// TODO: convert ASN1_GENERALIZEDTIME to epoch time?
		//       new API: ASN1_TIME_diff() requires openssl 1.0.2
		//       epoch time might be better for post processing
		
		// NOTE: this is for human readable time format
		//if (!ASN1_GENERALIZEDTIME_print(bio, (ASN1_GENERALIZEDTIME *)data))
		//	goto err;
		
		// NOTE: this is printing the raw string which is also understandable
		//       since this is smaller, let's keep ASN1_GENERALIZEDTIME as this for now?
		ASN1_GENERALIZEDTIME *tmp = (ASN1_GENERALIZEDTIME *)data;
		BIO_write(bio, tmp->data, tmp->length);	
		}

	else
		goto err;
	
	new_len = BIO_read(bio, buf, buf_len);
err:	
	BIO_free_all(bio);
	return new_len;
	}

//ANS1 OCTET string to c string
static int ASN1_OCTET_STRING_to_cstr(char *buf, int len, void *data)
	{
	return ANS1_to_cstr(buf, len, data, V_ASN1_OCTET_STRING);
	}

//ANS1 BIT string to c string
static int ASN1_BIT_STRING_to_cstr(char *buf, int len, void *data)
	{
	return ANS1_to_cstr(buf, len, data, V_ASN1_BIT_STRING);
	}

//ANS1 integer to c string
static int ASN1_INTEGER_to_cstr(char *buf, int len, void *data)
	{
	return ANS1_to_cstr(buf, len, data, V_ASN1_INTEGER);
	}

//ANS1 object to c string
static int ASN1_OBJECT_to_cstr(char *buf, int len, void *data)
	{
	return ANS1_to_cstr(buf, len, data, V_ASN1_OBJECT);
	}

//ASN1_GENERALIZEDTIME to c string
static int ASN1_GENERALIZEDTIME_to_cstr(char *buf, int len, void *data)
	{
	return ANS1_to_cstr(buf, len, data, V_ASN1_GENERALIZEDTIME);
	}

//CENERAL XXX to c string
static int GENERAL_NAME_to_cstr(char *buf, int buf_len, void *data)
	{
	if (data == NULL || buf == NULL || buf_len <= 0)
		return -1;
	int new_len = -1;
	BIO *bio = BIO_new(BIO_s_mem());
	memset(buf, 0, buf_len);
	if (GENERAL_NAME_print(bio, (GENERAL_NAME *)data) <= 0)
		goto err;
	new_len = BIO_read(bio, buf, buf_len);
err:
	BIO_free_all(bio);
	return new_len;
	}

//OCSP respond id to c string
static int OCSP_RESPID_to_cstr(char *buf, int buf_len, OCSP_RESPID *resp_id)
	{
	if (resp_id == NULL || buf == NULL || buf_len <= 0)
		return -1;
	int new_len = -1;
	BIO *bio = BIO_new(BIO_s_mem());
	memset(buf, 0, buf_len);
	if (resp_id->type == V_OCSP_RESPID_NAME)
		{
		if (X509_NAME_print_ex(bio, resp_id->value.byName, 0, XN_FLAG_ONELINE) <=0)
			goto err;
		}
	else if (resp_id->type == V_OCSP_RESPID_KEY)
		{
		if (i2a_ASN1_STRING(bio, resp_id->value.byKey, V_ASN1_OCTET_STRING) <= 0)
			goto err;
		}
	else
		goto err;
	new_len = BIO_read(bio, buf, buf_len);
err:
	BIO_free_all(bio);
	return new_len;
	}

//print out a cert id for debug
static void ocsp_print_cert_id(OCSP_CERTID *cid)
	{
	if (cid == NULL)
		return;
	char buf[OCSP_STRING_BUF_SIZE];
	int len = sizeof(buf);
	memset(buf, 0, len);
	int new_len = -1;
	
	//print hashAlgorithm
	new_len = ASN1_OBJECT_to_cstr(buf, len, (void *)(cid->hashAlgorithm->algorithm));
	StringVal hashAlgorithm = StringVal(new_len, buf);
	printf("[%d]hashAlgorithm: %s\n", new_len, hashAlgorithm.CheckString());

	//print issuerNameHash
	new_len = ASN1_OCTET_STRING_to_cstr(buf, len, (void *)(cid->issuerNameHash));
	StringVal issuerNameHash = StringVal(new_len, buf);
	printf("[%d]issuerNameHash: %s\n", new_len, issuerNameHash.CheckString());

	//print issuerKeyHash
	new_len = ASN1_OCTET_STRING_to_cstr(buf, len, (void *)(cid->issuerKeyHash));
	StringVal issuerKeyHash = StringVal(new_len, buf);
	printf("[%d]issuerKeyHash: %s\n", new_len, issuerKeyHash.CheckString());

	//print serialNumber
	new_len = ASN1_INTEGER_to_cstr(buf, len, (void *)(cid->issuerKeyHash));
	StringVal serialNumber = StringVal(new_len, buf);
	printf("[%d]serialNumber: %s\n", new_len, serialNumber.CheckString());
	}

//fill in cert id
static void ocsp_fill_cert_id(OCSP_CERTID *cert_id, RecordVal *d)
	{
	if (d == NULL || cert_id == NULL)
		return;
	char buf[OCSP_STRING_BUF_SIZE];
	int buf_len = sizeof(buf);
	memset(buf, 0, buf_len);

	//hashAlgorithm
	int len = -1;
	len = ASN1_OBJECT_to_cstr(buf, buf_len, (void *)(cert_id->hashAlgorithm->algorithm));
	if (len > 0)
		d->Assign(0, new StringVal(len, buf));
	
	//issuerNameHash
	len = -1;
	len = ASN1_OCTET_STRING_to_cstr(buf, buf_len, (void *)(cert_id->issuerNameHash));
	if (len > 0)
		d->Assign(1, new StringVal(len, buf));
	
	//issuerKeyHash
	len = -1;
	len = ASN1_OCTET_STRING_to_cstr(buf, buf_len, (void *)(cert_id->issuerKeyHash));
	if (len > 0)
		d->Assign(2, new StringVal(len, buf));
	
	//serialNumber
	len = -1;
	len = ASN1_INTEGER_to_cstr(buf, buf_len, (void *)(cert_id->issuerKeyHash));
	if (len > 0)
		d->Assign(3, new StringVal(len, buf));
	}

file_analysis::Analyzer* OCSP::Instantiate(RecordVal* args, File* file)
	{
	Val* ocsp_type = get_extract_field_val(args, "ocsp_type");
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

// parse OCSP request or response and send data to bro scriptland
bool file_analysis::OCSP::EndOfFile()
	{
	OCSP_REQUEST  *req     = NULL;
	OCSP_RESPONSE *resp    = NULL;
	
	const unsigned char* ocsp_char = reinterpret_cast<const unsigned char*>(ocsp_data.data());
	
	if (ocsp_type == "request")
		{
		req = d2i_OCSP_REQUEST(NULL, &ocsp_char, ocsp_data.size());
		if (!req)
			{
			reporter->Weird(fmt("OPENSSL Could not parse OCSP request (fuid %s)", GetFile()->GetID().c_str()));
			goto ocsp_cleanup;
			}
		
		//parse request into record
		OCSP_REQVal* req_val = new OCSP_REQVal(req);
		RecordVal* req_record = ParseRequest(req_val);
		if (!req_record)
			{
			reporter->Weird(fmt("Internal fail to parse OCSP request (fuid %s)", GetFile()->GetID().c_str()));
			Unref(req_val);
			goto ocsp_cleanup;
			}

		// and send the record on to scriptland
		val_list* vl = new val_list();
		vl->append(GetFile()->GetVal()->Ref());
		vl->append(req_val->Ref());
		vl->append(req_record->Ref());
		mgr.QueueEvent(ocsp_request, vl);		

		Unref(req_val);
		Unref(req_record);
		}
	else if (ocsp_type == "response")
		{
		resp = d2i_OCSP_RESPONSE(NULL, &ocsp_char, ocsp_data.size());
		if (!resp)
			{
			reporter->Weird(fmt("OPENSSL Could not parse OCSP response (fuid %s)", GetFile()->GetID().c_str()));
			goto ocsp_cleanup;
			}
		
		//parse request into record
		OCSP_RESPVal* resp_val = new OCSP_RESPVal(resp);
		RecordVal* resp_record = ParseResponse(resp_val);
		if (!resp_record)
			{
			reporter->Weird(fmt("Internal fail to parse OCSP response (fuid %s)", GetFile()->GetID().c_str()));
			Unref(resp_val);
			goto ocsp_cleanup;
			}

		// and send the record on to scriptland
		val_list* vl = new val_list();
		vl->append(GetFile()->GetVal()->Ref());
		vl->append(resp_val->Ref());
		vl->append(resp_record->Ref());
		mgr.QueueEvent(ocsp_response, vl);

		Unref(resp_val);
		Unref(resp_record);
		}
	else
	  reporter->Weird(fmt("the given argument of ocsp_type (%s) is not recognized", ocsp_type.c_str()));
ocsp_cleanup:
	//if (resp)
	//	OCSP_RESPONSE_free(resp);
	//if (req)
	//	OCSP_REQUEST_free(req);
	return false;
}

// parse OCSP request and trigger event
RecordVal *file_analysis::OCSP::ParseRequest(OCSP_REQVal *req_val)
	{
	if (req_val == NULL)
		return NULL;
	OCSP_REQUEST *req     = NULL;
	OCSP_ONEREQ  *one_req = NULL;
	OCSP_CERTID  *cert_id = NULL;
	OCSP_REQINFO *inf     = NULL;
	//OCSP_SIGNATURE *sig  = NULL;

	RecordVal* ocsp_req_record = NULL;
	VectorVal* all_req_bro = NULL;
	
	int req_count = -1, i = -1, len = -1;
	long version = -1;

	req = req_val->GetReq();
	if (req == NULL)
		return NULL;
	
	char buf[OCSP_STRING_BUF_SIZE];
	int buf_len = sizeof(buf);
	memset(buf, 0, buf_len);
	
	inf = req->tbsRequest;
	//sig = req->optionalSignature;
	if (inf == NULL)
		return NULL;

	ocsp_req_record = new RecordVal(BifType::Record::OCSP::Request);
	if (!ocsp_req_record)
		{
		reporter->Error("Cannot create OCSP request structure: Internal memory error");
		return NULL;
		}

	//version
	version = ASN1_INTEGER_get(inf->version);
	if (version != -1)
		ocsp_req_record->Assign(0, new Val((uint64)version, TYPE_COUNT));
	
	//requestorName
	if (inf->requestorName != NULL)
		{
		len = -1;
		len = GENERAL_NAME_to_cstr(buf, buf_len, (void *)(inf->requestorName));
		if (len > 1)
			ocsp_req_record->Assign(1, new StringVal(len, buf));
		}
	
	//deal with details of the request
	req_count = OCSP_request_onereq_count(req);
	if (req_count <= 0)
		goto clean_up;
	for (i=0; i<req_count; i++)
		{
		one_req = OCSP_request_onereq_get0(req, i);
		cert_id = OCSP_onereq_get0_id(one_req);
		if (all_req_bro == NULL)
			all_req_bro = new VectorVal(internal_type("ocsp_req_vec")->AsVectorType());
		RecordVal *one_req_bro = new RecordVal(BifType::Record::OCSP::OneReq);

		ocsp_fill_cert_id(cert_id, one_req_bro);		
		all_req_bro->Assign(all_req_bro->Size(), one_req_bro);
		}
	
	if (all_req_bro != NULL)
		ocsp_req_record->Assign(2, all_req_bro);
clean_up:
	return ocsp_req_record;
}

// parse OCSP response and trigger event
RecordVal *file_analysis::OCSP::ParseResponse(OCSP_RESPVal *resp_val)
	{
	if (resp_val == NULL)
		return NULL;

	OCSP_RESPONSE   *resp        = NULL;
	OCSP_RESPBYTES  *resp_bytes  = NULL;
	OCSP_CERTID     *cert_id     = NULL;
	OCSP_BASICRESP  *basic_resp  = NULL;
	OCSP_RESPDATA   *resp_data   = NULL;
	OCSP_RESPID     *resp_id     = NULL;
	OCSP_SINGLERESP *single_resp = NULL;	
	
	//OCSP_CERTSTATUS *cst = NULL;
	//OCSP_REVOKEDINFO *rev = NULL;

        RecordVal *ocsp_resp_record = NULL;
	VectorVal *all_resp_bro  = NULL;
	
	int resp_count = -1, status = -1, i = -1, len = -1;
	long version = -1;
	
	resp = resp_val->GetResp();
	if (resp == NULL)
		return NULL;	

  	char buf[OCSP_STRING_BUF_SIZE];
	int buf_len = sizeof(buf);
	memset(buf, 0, buf_len);

	ocsp_resp_record = new RecordVal(BifType::Record::OCSP::Response);
	if (!ocsp_resp_record)
		{
		reporter->Error("Cannot create OCSP response structure: Internal memory error");
		return NULL;
		}

	//responseStatus
	status = OCSP_response_status(resp);
	const char *status_str = OCSP_response_status_str(status);
	ocsp_resp_record->Assign(0, new StringVal(strlen(status_str), status_str));	

	//responseType
	resp_bytes = resp->responseBytes;
	if (!resp_bytes)
		goto clean_up;
	len = -1;
	len = ASN1_OBJECT_to_cstr(buf, buf_len, (void *)(resp_bytes->responseType));
	if (len > 0)
		ocsp_resp_record->Assign(1, new StringVal(len, buf));
	
	//get the basic response
	basic_resp = OCSP_response_get1_basic(resp);
	if (!basic_resp)
		goto clean_up;
	resp_data = basic_resp->tbsResponseData;
	if (!resp_data)
		goto clean_up;

	//version
	version = ASN1_INTEGER_get(resp_data->version);
	if (version != -1)
		ocsp_resp_record->Assign(2, new Val((uint64)version, TYPE_COUNT));

	//responderID
	resp_id = resp_data->responderId;
	len = -1;
	len = OCSP_RESPID_to_cstr(buf, buf_len, resp_id);
	if (len > 0)
		ocsp_resp_record->Assign(3, new StringVal(len, buf));

	//producedAt
	len = -1;
	len = ASN1_GENERALIZEDTIME_to_cstr(buf, buf_len, (void *)(resp_data->producedAt));
	if (len > 0)
		ocsp_resp_record->Assign(4, new StringVal(len, buf));

	//responses
	resp_count = sk_OCSP_SINGLERESP_num(resp_data->responses);
	if (resp_count <= 0)
		goto clean_up;
	for (i=0; i<resp_count; i++)
		{
		single_resp = sk_OCSP_SINGLERESP_value(resp_data->responses, i);
		if (!single_resp)
			continue;
		if (all_resp_bro == NULL)
			all_resp_bro = new VectorVal(internal_type("ocsp_resp_vec")->AsVectorType());
		RecordVal *single_resp_bro = new RecordVal(BifType::Record::OCSP::SingleResp);

		//cert id
		cert_id = single_resp->certId;
		ocsp_fill_cert_id(cert_id, single_resp_bro);

		//certStatus
		const char *cert_status_str = OCSP_cert_status_str(single_resp->certStatus->type);
		single_resp_bro->Assign(4, new StringVal(strlen(cert_status_str), cert_status_str));

		//thisUpdate
		len = -1;
		len = ASN1_GENERALIZEDTIME_to_cstr(buf, buf_len, (void *)(single_resp->thisUpdate));
		if (len > 0)
			single_resp_bro->Assign(5, new StringVal(len, buf));

		//nextUpdate
		len = -1;
		len = ASN1_GENERALIZEDTIME_to_cstr(buf, buf_len, (void *)(single_resp->nextUpdate));
		if (len > 0)
			single_resp_bro->Assign(6, new StringVal(len, buf));

		all_resp_bro->Assign(all_resp_bro->Size(), single_resp_bro);
		}
	if (all_resp_bro != NULL)
		ocsp_resp_record->Assign(5, all_resp_bro);

	//signatureAlgorithm
	if (basic_resp->signatureAlgorithm)
		{
		len = -1;
		len = ASN1_OBJECT_to_cstr(buf, buf_len, (void *)(basic_resp->signatureAlgorithm->algorithm));
		if (len > 0)
			ocsp_resp_record->Assign(6, new StringVal(len, buf));
		}
	//signature
	if (basic_resp->signature)
		{
		len = -1;
		len = ASN1_BIT_STRING_to_cstr(buf, buf_len, (void *)(basic_resp->signature));
		if (len > 0)
			ocsp_resp_record->Assign(7, new StringVal(len, buf));
		}
clean_up:
	return ocsp_resp_record;
}

//OCSP_REQVal
OCSP_REQVal::OCSP_REQVal(OCSP_REQUEST* arg_ocsp_req) : OpaqueVal(ocsp_req_opaque_type)
	{
	ocsp_req = arg_ocsp_req;
	}

OCSP_REQVal::OCSP_REQVal() : OpaqueVal(ocsp_req_opaque_type)
	{
	ocsp_req = NULL;
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
	unsigned char *buf = NULL;
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
	ocsp_req = d2i_OCSP_REQUEST(NULL, const_cast<const unsigned char**>(&opensslbuf), length);
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
	ocsp_resp = NULL;
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
	unsigned char *buf = NULL;
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
	ocsp_resp = d2i_OCSP_RESPONSE(NULL, const_cast<const unsigned char**>(&opensslbuf), length);
	delete[] ocsp_resp_buf;
	if ( !ocsp_resp )
		return false;
	return true;
	}
