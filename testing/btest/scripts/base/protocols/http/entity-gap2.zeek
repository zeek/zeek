# @TEST-EXEC: zeek -r $TRACES/http/entity_gap2.trace %INPUT
# @TEST-EXEC: btest-diff entity_data
# @TEST-EXEC: btest-diff extract_files/file0

global f = open("entity_data");
global fn = 0;

event http_entity_data(c: connection, is_orig: bool, length: count,
                       data: string)
	{
	print f, data;
	}

event content_gap(c: connection, is_orig: bool, seq: count, length: count)
	{
	print f, fmt("<%d byte gap>", length);
	}

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
					   [$extract_filename=fmt("file%d", fn)]);
	++fn;
	}
