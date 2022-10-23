##! Enable logging of OCSP responses.

module OCSP;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	## The record type which contains the fields of the OCSP log.
	type Info: record {
		## Time when the OCSP reply was encountered.
		ts: time &log;
		## File id of the OCSP reply.
		id: string &log;
		## Hash algorithm used to generate issuerNameHash and issuerKeyHash.
		hashAlgorithm: string &log;
		## Hash of the issuer's distinguished name.
		issuerNameHash: string &log;
		## Hash of the issuer's public key.
		issuerKeyHash: string &log;
		## Serial number of the affected certificate.
		serialNumber: string &log;
		## Status of the affected certificate.
		certStatus: string &log;
		## Time at which the certificate was revoked.
		revoketime: time &log &optional;
		## Reason for which the certificate was revoked.
		revokereason: string &log &optional;
		## The time at which the status being shows is known to have been correct.
		thisUpdate: time &log;
		## The latest time at which new information about the status of the certificate will be available.
		nextUpdate: time &log &optional;
	};

	## Event that can be handled to access the OCSP record
	## as it is sent to the logging framework.
	global log_ocsp: event(rec: Info);
}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_ocsp, $path="ocsp", $policy=log_policy]);
	Files::register_for_mime_type(Files::ANALYZER_OCSP_REPLY, "application/ocsp-response");
	}

event ocsp_response_certificate(f: fa_file, hashAlgorithm: string, issuerNameHash: string, issuerKeyHash: string, serialNumber: string, certStatus: string, revoketime: time, revokereason: string, thisUpdate: time, nextUpdate: time)
	{
	local wr = OCSP::Info($ts=f$info$ts, $id=f$id, $hashAlgorithm=hashAlgorithm, $issuerNameHash=issuerNameHash,
			      $issuerKeyHash=issuerKeyHash, $serialNumber=serialNumber, $certStatus=certStatus,
			      $thisUpdate=thisUpdate);

	if ( revokereason != "" )
		wr$revokereason = revokereason;
	if ( time_to_double(revoketime) != 0 )
		wr$revoketime = revoketime;
	if ( time_to_double(nextUpdate) != 0 )
		wr$nextUpdate = nextUpdate;

	Log::write(LOG, wr);
	}
