@load base/frameworks/files
@load base/utils/paths

module FileExtract;

export {
	## The prefix where files are extracted to.
	const prefix = "./extract_files/" &redef;

	redef record Files::Info += {
		## Local filenames of extracted file.
		extracted: string &optional &log;
	};

	redef record Files::AnalyzerArgs += {
		## The local filename to which to write an extracted file.
		## This field is used in the core by the extraction plugin
		## to know where to write the file to.  It's also optional
		extract_filename: string &optional;
	};
}

function on_add(f: fa_file, args: Files::AnalyzerArgs)
	{
	if ( ! args?$extract_filename )
		args$extract_filename = cat("extract-", f$source, "-", f$id);

	f$info$extracted = args$extract_filename;
	args$extract_filename = build_path_compressed(prefix, args$extract_filename);
	}

event bro_init() &priority=10
	{
	Files::register_analyzer_add_callback(Files::ANALYZER_EXTRACT, on_add);

	# Create the extraction directory.
	mkdir(prefix);
	}