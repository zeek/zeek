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
	if ( !ssl_cert )
		{
		reporter->Error("Could not parse X509 certificate");
		return false;
		}

	char buf[256]; // we need a buffer for some of the openssl functions
	memset(buf, 0, 256);	
	
	RecordVal* pX509Cert = new RecordVal(BifType::Record::X509::Certificate);
	BIO *bio = BIO_new(BIO_s_mem());

	pX509Cert->Assign(0, new Val((uint64) X509_get_version(ssl_cert), TYPE_COUNT));
	i2a_ASN1_INTEGER(bio, X509_get_serialNumber(ssl_cert));
	int len = BIO_read(bio, &(*buf), sizeof buf);
	pX509Cert->Assign(1, new StringVal(len, buf));

	X509_NAME_print_ex(bio, X509_get_subject_name(ssl_cert), 0, XN_FLAG_RFC2253);
	len = BIO_gets(bio, &(*buf), sizeof buf);
	pX509Cert->Assign(2, new StringVal(len, buf));
	X509_NAME_print_ex(bio, X509_get_issuer_name(ssl_cert), 0, XN_FLAG_RFC2253);
	len = BIO_gets(bio, &(*buf), sizeof buf);
	pX509Cert->Assign(3, new StringVal(len, buf));
	BIO_free(bio);

	pX509Cert->Assign(4, new Val(get_time_from_asn1(X509_get_notBefore(ssl_cert)), TYPE_TIME));
	pX509Cert->Assign(5, new Val(get_time_from_asn1(X509_get_notAfter(ssl_cert)), TYPE_TIME));

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
			{
			pX509Cert->Assign(8, new StringVal("dsa"));
			}
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
			pX509Cert->Assign(11, key_curve(pkey));
			}
#endif

		unsigned int length = key_length(pkey);
		if ( length > 0 ) 
			pX509Cert->Assign(9, new Val(length, TYPE_COUNT));
		}

	val_list* vl = new val_list();
	vl->append(GetFile()->GetVal()->Ref());
	vl->append(pX509Cert);

	mgr.QueueEvent(x509_cert, vl);
	
	return false;
	}

StringVal* file_analysis::X509::key_curve(EVP_PKEY *key)
	{
	assert(key != NULL);

#ifdef OPENSSL_NO_EC
	// well, we do not have EC-Support...
	return NULL;
#else 
	if ( key->type != EVP_PKEY_EC ) {
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

unsigned int file_analysis::X509::key_length(EVP_PKEY *key) 
	{
	assert(key != NULL);
	unsigned int length;

	switch(key->type) {
    	case EVP_PKEY_RSA:
      		length = BN_num_bits(key->pkey.rsa->n);
      		break;
    	case EVP_PKEY_DSA:
      		length = BN_num_bits(key->pkey.dsa->p);
      		break;
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC:
		{
		const EC_GROUP *group;       
		BIGNUM* ec_order;
		ec_order = BN_new();
		if ( !ec_order ) 
			// could not malloc bignum?
			return 0;

		if ( (group = EC_KEY_get0_group(key->pkey.ec)) == NULL) 
			// unknown ex-group
			return 0;

		if (!EC_GROUP_get_order(group, ec_order, NULL)) 
			// could not get ec-group-order
			return 0;

		length = BN_num_bits(ec_order);
		BN_free(ec_order);
		break;
		}
#endif
	default:
		return 0; // unknown public key type
	}

	return length;
	}

double file_analysis::X509::get_time_from_asn1(const ASN1_TIME * atime)
	{
	time_t lResult = 0;

	char lBuffer[24];
	char * pBuffer = lBuffer;

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

