@load base/frameworks/files

module FileHash;

export {
	redef record Files::Info += {
		## An MD5 digest of the file contents.
		md5: string &log &optional;

		## A SHA1 digest of the file contents.
		sha1: string &log &optional;

		## A SHA256 digest of the file contents.
		sha256: string &log &optional;
	};

}

event file_hash(f: fa_file, kind: string, hash: string) &priority=5
	{
	switch ( kind ) {
	case "md5":
		f$info$md5 = hash;
		break;
	case "sha1":
		f$info$sha1 = hash;
		break;
	case "sha256":
		f$info$sha256 = hash;
		break;
	}
	}
