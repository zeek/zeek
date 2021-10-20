module Files;

export {
	redef record Files::Info += {
		## The information density of the contents of the file,
		## expressed as a number of bits per character.
		entropy: double &log &optional;
	};
}

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_ENTROPY);
	}

event file_entropy(f: fa_file, ent: entropy_test_result)
	{
	f$info$entropy = ent$entropy;
	}
