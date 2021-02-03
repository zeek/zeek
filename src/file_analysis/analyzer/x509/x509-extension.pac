# Binpac analyzer for X.509 extensions
# we just use it for the SignedCertificateTimestamp at the moment

%include binpac.pac
%include zeek.pac

%extern{
#include "zeek/file_analysis/File.h"

#include "zeek/file_analysis/analyzer/x509/types.bif.h"
#include "zeek/file_analysis/analyzer/x509/events.bif.h"
%}

analyzer X509Extension withcontext {
	connection: MockConnection;
	flow:       SignedCertTimestampExt;
};

connection MockConnection(zeek_analyzer: ZeekFileAnalyzer) {
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

		zeek::event_mgr.Enqueue(x509_ocsp_ext_signed_certificate_timestamp,
			zeek_analyzer()->GetFile()->ToVal(),
			zeek::val_mgr->Count(version),
			zeek::make_intrusive<zeek::StringVal>(logid.length(), reinterpret_cast<const char*>(logid.begin())),
			zeek::val_mgr->Count(timestamp),
			zeek::val_mgr->Count(digitally_signed_algorithms->HashAlgorithm()),
			zeek::val_mgr->Count(digitally_signed_algorithms->SignatureAlgorithm()),
			zeek::make_intrusive<zeek::StringVal>(digitally_signed_signature.length(), reinterpret_cast<const char*>(digitally_signed_signature.begin()))
			);

		return true;
		%}
};

refine typeattr SignedCertificateTimestamp += &let {
	proc : bool = $context.connection.proc_signedcertificatetimestamp(rec, version, logid, timestamp, digitally_signed_algorithms, digitally_signed_signature);
};
