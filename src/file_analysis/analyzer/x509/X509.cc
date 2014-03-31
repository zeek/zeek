// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "X509.h"
#include "Event.h"

#include "events.bif.h"
#include "types.bif.h"

#include "file_analysis/Manager.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/opensslconf.h>

using namespace file_analysis;

IMPLEMENT_SERIAL(X509Val, SER_X509_VAL);

file_analysis::X509::X509(RecordVal* args, file_analysis::File* file)
	: file_analysis::Analyzer(file_mgr->GetComponentTag("X509"), args, file)
	{
	cert_data.clear();
	}

bool file_analysis::X509::DeliverStream(const u_char* data, uint64 len)
	{
	// just add it to the data we have so far, since we cannot do anything else anyways...
	cert_data.append(reinterpret_cast<const char*>(data), len);
	return true;
	}

bool file_analysis::X509::Undelivered(uint64 offset, uint64 len)
	{
	return false;
	}

bool file_analysis::X509::EndOfFile()
	{
	// ok, now we can try to parse the certificate with openssl. Should
	// be rather straightforward...
	const unsigned char* cert_char = reinterpret_cast<const unsigned char*>(cert_data.data());

	::X509* ssl_cert = d2i_X509(NULL, &cert_char, cert_data.size());
	if ( ! ssl_cert )
		{
		reporter->Error("Could not parse X509 certificate (fuid %s)", GetFile()->GetID().c_str());
		return false;
		}

	X509Val* cert_val = new X509Val(ssl_cert); // cert_val takes ownership of ssl_cert

	RecordVal* cert_record = ParseCertificate(cert_val); // parse basic information into record

	// and send the record on to scriptland
	val_list* vl = new val_list();
	vl->append(GetFile()->GetVal()->Ref());
	vl->append(cert_val->Ref());
	vl->append(cert_record->Ref()); // we Ref it here, because we want to keep a copy around for now...
	mgr.QueueEvent(x509_certificate, vl);

	// after parsing the certificate - parse the extensions...

	int num_ext = X509_get_ext_count(ssl_cert);
	for ( int k = 0; k < num_ext; ++k )
		{
		X509_EXTENSION* ex = X509_get_ext(ssl_cert, k);
		if ( ! ex )
			continue;

		ParseExtension(ex);
		}

	// X509_free(ssl_cert); We do _not_ free the certificate here. It is refcounted
	// inside the X509Val that is sent on in the cert record to scriptland.
	//
	// The certificate will be freed when the last X509Val is Unref'd.

	Unref(cert_record); // Unref the RecordVal that we kept around from ParseCertificate
	Unref(cert_val); // Same for cert_val

	return false;
	}

RecordVal* file_analysis::X509::ParseCertificate(X509Val* cert_val)
	{
	::X509* ssl_cert = cert_val->GetCertificate();

	char buf[256]; // we need a buffer for some of the openssl functions
	memset(buf, 0, sizeof(buf));

	RecordVal* pX509Cert = new RecordVal(BifType::Record::X509::Certificate);
	BIO *bio = BIO_new(BIO_s_mem());

	pX509Cert->Assign(0, new Val((uint64) X509_get_version(ssl_cert) + 1, TYPE_COUNT));
	i2a_ASN1_INTEGER(bio, X509_get_serialNumber(ssl_cert));
	int len = BIO_read(bio, &(*buf), sizeof(buf));
	pX509Cert->Assign(1, new StringVal(len, buf));

	X509_NAME_print_ex(bio, X509_get_subject_name(ssl_cert), 0, XN_FLAG_RFC2253);
	len = BIO_gets(bio, &(*buf), sizeof(buf));
	pX509Cert->Assign(2, new StringVal(len, buf));
	X509_NAME_print_ex(bio, X509_get_issuer_name(ssl_cert), 0, XN_FLAG_RFC2253);
	len = BIO_gets(bio, &(*buf), sizeof(buf));
	pX509Cert->Assign(3, new StringVal(len, buf));
	BIO_free(bio);

	pX509Cert->Assign(4, new Val(GetTimeFromAsn1(X509_get_notBefore(ssl_cert)), TYPE_TIME));
	pX509Cert->Assign(5, new Val(GetTimeFromAsn1(X509_get_notAfter(ssl_cert)), TYPE_TIME));

	// we only read 255 bytes because byte 256 is always 0.
	// if the string is longer than 255, that will be our null-termination,
	// otherwhise i2t does null-terminate.
	if ( ! i2t_ASN1_OBJECT(buf, 255, ssl_cert->cert_info->key->algor->algorithm) )
		buf[0] = 0;

	pX509Cert->Assign(6, new StringVal(buf));

	if ( ! i2t_ASN1_OBJECT(buf, 255, ssl_cert->sig_alg->algorithm) )
		buf[0] = 0;

	pX509Cert->Assign(7, new StringVal(buf));

	// Things we can do when we have the key...
	EVP_PKEY *pkey = X509_extract_key(ssl_cert);
	if ( pkey != NULL )
		{
		if ( pkey->type == EVP_PKEY_DSA )
			pX509Cert->Assign(8, new StringVal("dsa"));

		else if ( pkey->type == EVP_PKEY_RSA )
			{
			pX509Cert->Assign(8, new StringVal("rsa"));

			char *exponent = BN_bn2dec(pkey->pkey.rsa->e);
			if ( exponent != NULL )
				{
				pX509Cert->Assign(10, new StringVal(exponent));
				OPENSSL_free(exponent);
				exponent = NULL;
				}
			}
#ifndef OPENSSL_NO_EC
		else if ( pkey->type == EVP_PKEY_EC )
			{
			pX509Cert->Assign(8, new StringVal("dsa"));
			pX509Cert->Assign(11, KeyCurve(pkey));
			}
#endif

		unsigned int length = KeyLength(pkey);
		if ( length > 0 )
			pX509Cert->Assign(9, new Val(length, TYPE_COUNT));
		}


	return pX509Cert;
	}

void file_analysis::X509::ParseExtension(X509_EXTENSION* ex)
	{
	char name[256];
	char oid[256];

	ASN1_OBJECT* ext_asn = X509_EXTENSION_get_object(ex);
	const char* short_name = OBJ_nid2sn(OBJ_obj2nid(ext_asn));

	OBJ_obj2txt(name, 255, ext_asn, 0);
	OBJ_obj2txt(oid, 255, ext_asn, 1);

	int critical = 0;
	if ( X509_EXTENSION_get_critical(ex) != 0 )
		critical = 1;

	BIO *bio = BIO_new(BIO_s_mem());
	if( ! X509V3_EXT_print(bio, ex, 0, 0))
		M_ASN1_OCTET_STRING_print(bio,ex->value);

	BIO_flush(bio);
	int length = BIO_pending(bio);

	// Use OPENSSL_malloc here. Using new or anything else can lead
	// to interesting, hard to debug segfaults.
	char *buffer = (char*) OPENSSL_malloc(length);
	BIO_read(bio, (void*)buffer, length);
	StringVal* ext_val = new StringVal(length, buffer);
	OPENSSL_free(buffer);
	BIO_free_all(bio);

	RecordVal* pX509Ext = new RecordVal(BifType::Record::X509::Extension);
	pX509Ext->Assign(0, new StringVal(name));

	if ( short_name and strlen(short_name) > 0 )
		pX509Ext->Assign(1, new StringVal(short_name));

	pX509Ext->Assign(2, new StringVal(oid));
	pX509Ext->Assign(3, new Val(critical, TYPE_BOOL));
	pX509Ext->Assign(4, ext_val);

	// send off generic extension event
	//
	// and then look if we have a specialized event for the extension we just
	// parsed. And if we have it, we send the specialized event on top of the
	// generic event that we just had. I know, that is... kind of not nice,
	// but I am not sure if there is a better way to do it...
	val_list* vl = new val_list();
	vl->append(GetFile()->GetVal()->Ref());
	vl->append(pX509Ext);

	mgr.QueueEvent(x509_extension, vl);

	// look if we have a specialized handler for this event...
	if ( OBJ_obj2nid(ext_asn) == NID_basic_constraints )
		ParseBasicConstraints(ex);

	else if ( OBJ_obj2nid(ext_asn) == NID_subject_alt_name )
		ParseSAN(ex);
	}

void file_analysis::X509::ParseBasicConstraints(X509_EXTENSION* ex)
	{
	assert(OBJ_obj2nid(X509_EXTENSION_get_object(ex)) == NID_basic_constraints);

	BASIC_CONSTRAINTS *constr = (BASIC_CONSTRAINTS *) X509V3_EXT_d2i(ex);

	if ( constr )
		{
		RecordVal* pBasicConstraint = new RecordVal(BifType::Record::X509::BasicConstraints);
		pBasicConstraint->Assign(0, new Val(constr->ca ? 1 : 0, TYPE_BOOL));

		if ( constr->pathlen )
			pBasicConstraint->Assign(1, new Val((int32_t) ASN1_INTEGER_get(constr->pathlen), TYPE_COUNT));

		val_list* vl = new val_list();
		vl->append(GetFile()->GetVal()->Ref());
		vl->append(pBasicConstraint);

		mgr.QueueEvent(x509_ext_basic_constraints, vl);
		}

	else
		reporter->Error("Certificate with invalid BasicConstraint. fuid %s", GetFile()->GetID().c_str());
	}

void file_analysis::X509::ParseSAN(X509_EXTENSION* ext)
	{
	assert(OBJ_obj2nid(X509_EXTENSION_get_object(ext)) == NID_subject_alt_name);

	GENERAL_NAMES *altname = (GENERAL_NAMES*)X509V3_EXT_d2i(ext);
	if ( ! altname )
		{
		reporter->Error("Could not parse subject alternative names. fuid %s", GetFile()->GetID().c_str());
		return;
		}

	VectorVal* names = 0;
	VectorVal* emails = 0;
	VectorVal* uris = 0;
	VectorVal* ips = 0;

	unsigned int otherfields = 0;

	for ( int i = 0; i < sk_GENERAL_NAME_num(altname); i++ )
		{
		GENERAL_NAME *gen = sk_GENERAL_NAME_value(altname, i);
		assert(gen);

		if ( gen->type == GEN_DNS || gen->type == GEN_URI || gen->type == GEN_EMAIL )
			{
			if ( ASN1_STRING_type(gen->d.ia5) != V_ASN1_IA5STRING )
				{
				reporter->Error("DNS-field does not contain an IA5String. fuid %s", GetFile()->GetID().c_str());
				continue;
				}

			const char* name = (const char*) ASN1_STRING_data(gen->d.ia5);
			StringVal* bs = new StringVal(name);

			switch ( gen->type )
				{
				case GEN_DNS:
					if ( names == 0 )
						names = new VectorVal(internal_type("string_vec")->AsVectorType());

					names->Assign(names->Size(), bs);
					break;

				case GEN_URI:
					if ( uris == 0 )
						uris = new VectorVal(internal_type("string_vec")->AsVectorType());

					uris->Assign(uris->Size(), bs);
					break;

				case GEN_EMAIL:
					if ( emails == 0 )
						emails = new VectorVal(internal_type("string_vec")->AsVectorType());

					emails->Assign(emails->Size(), bs);
					break;
				}
			}

		else if ( gen->type == GEN_IPADD )
			{
				if ( ips == 0 )
					ips = new VectorVal(internal_type("addr_vec")->AsVectorType());

				uint32* addr = (uint32*) gen->d.ip->data;

				if( gen->d.ip->length == 4 )
					ips->Assign(ips->Size(), new AddrVal(*addr));

				else if ( gen->d.ip->length == 16 )
					ips->Assign(ips->Size(), new AddrVal(addr));

				else
					{
					reporter->Error("Weird IP address length %d in subject alternative name. fuid %s", gen->d.ip->length, GetFile()->GetID().c_str());
					continue;
					}
			}

		else
			{
			// reporter->Error("Subject alternative name contained unsupported fields. fuid %s", GetFile()->GetID().c_str());
			// This happens quite often - just mark it
			otherfields = 1;
			continue;
			}
		}

		RecordVal* sanExt = new RecordVal(BifType::Record::X509::SubjectAlternativeName);

		if ( names != 0 )
			sanExt->Assign(0, names);

		if ( uris != 0 )
			sanExt->Assign(1, uris);

		if ( emails != 0 )
			sanExt->Assign(2, emails);

		if ( ips != 0 )
			sanExt->Assign(3, ips);

		sanExt->Assign(4, new Val(otherfields, TYPE_BOOL));

		val_list* vl = new val_list();
		vl->append(GetFile()->GetVal()->Ref());
		vl->append(sanExt);
		mgr.QueueEvent(x509_ext_subject_alternative_name, vl);
	}

StringVal* file_analysis::X509::KeyCurve(EVP_PKEY *key)
	{
	assert(key != NULL);

#ifdef OPENSSL_NO_EC
	// well, we do not have EC-Support...
	return NULL;
#else
	if ( key->type != EVP_PKEY_EC )
		{
		// no EC-key - no curve name
		return NULL;
		}

	const EC_GROUP *group;
	int nid;
	if ( (group = EC_KEY_get0_group(key->pkey.ec)) == NULL)
		// I guess we could not parse this
		return NULL;

	nid = EC_GROUP_get_curve_name(group);
	if ( nid == 0 )
		// and an invalid nid...
		return NULL;

	const char * curve_name = OBJ_nid2sn(nid);
	if ( curve_name == NULL )
		return NULL;

	return new StringVal(curve_name);
#endif
	}

unsigned int file_analysis::X509::KeyLength(EVP_PKEY *key)
	{
	assert(key != NULL);

	switch(key->type) {
	case EVP_PKEY_RSA:
		return BN_num_bits(key->pkey.rsa->n);

	case EVP_PKEY_DSA:
		return BN_num_bits(key->pkey.dsa->p);

#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		{
		BIGNUM* ec_order = BN_new();
		if ( ! ec_order )
			// could not malloc bignum?
			return 0;

		const EC_GROUP *group = EC_KEY_get0_group(key->pkey.ec);
		if ( ! group )
			// unknown ex-group
			return 0;

		if ( ! EC_GROUP_get_order(group, ec_order, NULL) )
			// could not get ec-group-order
			return 0;

		unsigned int length = BN_num_bits(ec_order);
		BN_free(ec_order);
		return length;
		}
#endif
	default:
		return 0; // unknown public key type
	}

	reporter->InternalError("cannot be reached");
	}

double file_analysis::X509::GetTimeFromAsn1(const ASN1_TIME* atime)
	{
	time_t lResult = 0;

	char lBuffer[24];
	char* pBuffer = lBuffer;

	size_t lTimeLength = atime->length;
	char * pString = (char *) atime->data;

	if ( atime->type == V_ASN1_UTCTIME )
		{
		if ( lTimeLength < 11 || lTimeLength > 17 )
			return 0;

		memcpy(pBuffer, pString, 10);
		pBuffer += 10;
		pString += 10;
		}

	else
		{
		if ( lTimeLength < 13 )
			return 0;

		memcpy(pBuffer, pString, 12);
		pBuffer += 12;
		pString += 12;
		}

	if ((*pString == 'Z') || (*pString == '-') || (*pString == '+'))
		{
		*(pBuffer++) = '0';
		*(pBuffer++) = '0';
		}

	else
		{
		*(pBuffer++) = *(pString++);
		*(pBuffer++) = *(pString++);

		// Skip any fractional seconds...
		if (*pString == '.')
			{
			pString++;
			while ((*pString >= '0') && (*pString <= '9'))
				pString++;
			}
		}

	*(pBuffer++) = 'Z';
	*(pBuffer++) = '\0';

	time_t lSecondsFromUTC;

	if ( *pString == 'Z' )
		lSecondsFromUTC = 0;

	else
		{
		if ((*pString != '+') && (pString[5] != '-'))
			return 0;

		lSecondsFromUTC = ((pString[1]-'0') * 10 + (pString[2]-'0')) * 60;
		lSecondsFromUTC += (pString[3]-'0') * 10 + (pString[4]-'0');

		if (*pString == '-')
			lSecondsFromUTC = -lSecondsFromUTC;
		}

	tm lTime;
	lTime.tm_sec  = ((lBuffer[10] - '0') * 10) + (lBuffer[11] - '0');
	lTime.tm_min  = ((lBuffer[8] - '0') * 10) + (lBuffer[9] - '0');
	lTime.tm_hour = ((lBuffer[6] - '0') * 10) + (lBuffer[7] - '0');
	lTime.tm_mday = ((lBuffer[4] - '0') * 10) + (lBuffer[5] - '0');
	lTime.tm_mon  = (((lBuffer[2] - '0') * 10) + (lBuffer[3] - '0')) - 1;
	lTime.tm_year = ((lBuffer[0] - '0') * 10) + (lBuffer[1] - '0');

	if ( lTime.tm_year < 50 )
		lTime.tm_year += 100; // RFC 2459

	lTime.tm_wday = 0;
	lTime.tm_yday = 0;
	lTime.tm_isdst = 0;  // No DST adjustment requested

	lResult = mktime(&lTime);

	if ( lResult )
		{
		if ( 0 != lTime.tm_isdst )
			lResult -= 3600;  // mktime may adjust for DST  (OS dependent)

		lResult += lSecondsFromUTC;
		}

	else
		lResult = 0;

	return lResult;
}

X509Val::X509Val(::X509* arg_certificate) : OpaqueVal(x509_opaque_type)
	{
	certificate = arg_certificate;
	}

X509Val::X509Val() : OpaqueVal(x509_opaque_type)
	{
	certificate = 0;
	}

X509Val::~X509Val()
	{
	if ( certificate )
		X509_free(certificate);
	}

::X509* X509Val::GetCertificate() const
	{
	return certificate;
	}

bool X509Val::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_X509_VAL, OpaqueVal);

	unsigned char *buf = NULL;

	int length = i2d_X509(certificate, &buf);

	if ( length < 0 )
		return false;

	bool res = SERIALIZE_STR(reinterpret_cast<const char*>(buf), length);

	OPENSSL_free(buf);
	return res;
	}

bool X509Val::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(OpaqueVal)

	int length;
	unsigned char *certbuf, *opensslbuf;

	if ( ! UNSERIALIZE_STR(reinterpret_cast<char **>(&certbuf), &length) )
		return false;

	opensslbuf = certbuf; // OpenSSL likes to shift pointers around. really.
	certificate = d2i_X509(NULL, const_cast<const unsigned char**>(&opensslbuf), length);
	delete[] certbuf;

	if ( !certificate )
		return false;

	return true;
	}
