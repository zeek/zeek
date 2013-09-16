
@load base/frameworks/files

module X509;

export {
	redef enum Log::ID += { LOG };
}

event x509_cert(f: fa_file, cert: X509::Certificate)
	{
	print cert;
	}

