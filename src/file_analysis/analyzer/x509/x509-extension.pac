# Binpac analyzer for X.509 extensions
# we just use it for the SignedCertificateTimestamp at the moment

%include binpac.pac
%include bro.pac

%extern{
#include "types.bif.h"
#include "file_analysis/File.h"
#include "events.bif.h"
%}

analyzer X509Extension withcontext {
	connection: MockConnection;
	flow:       SignedCertTimestampExt;
};

connection MockConnection(bro_analyzer: BroFileAnalyzer) {
	upflow = SignedCertTimestampExt;
	downflow = SignedCertTimestampExt;
};

%include x509-signed_certificate_timestamp.pac

# The base record
type HandshakeRecord() = record {
	signed_certificate_timestamp_list: SignedCertificateTimestampList(this)[] &transient;
} &byteorder = bigendian;

flow SignedCertTimestampExt {
	flowunit = HandshakeRecord withcontext(connection, this);
};

refine connection MockConnection += {

	function proc_signedcertificatetimestamp(rec: HandshakeRecord, version: uint8, logid: const_bytestring, timestamp: uint64, digitally_signed_algorithms: SignatureAndHashAlgorithm, digitally_signed_signature: const_bytestring) : bool
		%{
		if ( ! x509_ocsp_ext_signed_certificate_timestamp )
			return true;

		mgr.Enqueue(x509_ocsp_ext_signed_certificate_timestamp,
			IntrusivePtr{NewRef{}, bro_analyzer()->GetFile()->GetVal()},
			val_mgr->Count(version),
			make_intrusive<StringVal>(logid.length(), reinterpret_cast<const char*>(logid.begin())),
			val_mgr->Count(timestamp),
			val_mgr->Count(digitally_signed_algorithms->HashAlgorithm()),
			val_mgr->Count(digitally_signed_algorithms->SignatureAlgorithm()),
			make_intrusive<StringVal>(digitally_signed_signature.length(), reinterpret_cast<const char*>(digitally_signed_signature.begin()))
			);

		return true;
		%}
};

refine typeattr SignedCertificateTimestamp += &let {
	proc : bool = $context.connection.proc_signedcertificatetimestamp(rec, version, logid, timestamp, digitally_signed_algorithms, digitally_signed_signature);
};
