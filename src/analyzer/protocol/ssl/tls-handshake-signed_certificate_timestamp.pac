# We keep this extension separate, because it also can be included in X.509 certificates.
# If included there, it uses the exact same syntax and we just symlink it from the X.509
# file analyzer tree.

type SignatureAndHashAlgorithm() = record {
	HashAlgorithm: uint8;
	SignatureAlgorithm: uint8;
}

type SignedCertificateTimestampList(rec: HandshakeRecord) = record {
	length: uint16;
	SCTs: SignedCertificateTimestamp(rec)[] &until($input.length() == 0);
} &length=length+2;

type SignedCertificateTimestamp(rec: HandshakeRecord) = record {
	# before - framing
	length: uint16;
	# from here: SignedCertificateTimestamp
	version: uint8;
	logid: bytestring &length=32;
	timestamp: uint64;
	extensions_length: uint16; # extensions are not actually defined yet, so we cannot parse them
	extensions: bytestring &length=extensions_length;
	digitally_signed_algorithms: SignatureAndHashAlgorithm;
	digitally_signed_signature_length: uint16;
	digitally_signed_signature: bytestring &length=digitally_signed_signature_length;
} &length=length+2;

