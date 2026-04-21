module ZIP;

export {
	type File: record {
		## True if from global directory header, false if from local file header
		global_: bool;
		## File ID associated with content analysis of this file. Only available for local
		## headers where file content has been further processed.
		fid: string &optional;
		## Name of file
		filename: string;
		## Timestamp of file
		time_: time;
		## Comment associated with file.
		comment: string;
		## Compression type
		compression: ZIP::CompressionMethod;
		## True if encrypted
		encrypted: bool;
	};
}

redef record fa_file += {
	zip_file: ZIP::File &optional;
};

event ZIP::file(f: fa_file, meta: ZIP::File) {
	f$zip_file = meta;
}

event file_state_remove(f: fa_file) {
	if ( ! f?$zip_file )
		return;

	f$info$filename = f$zip_file$filename;
}
