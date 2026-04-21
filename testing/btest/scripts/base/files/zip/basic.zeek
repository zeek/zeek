# @TEST-DOC: Test ZIP analyzer with a download of a simple ZIP file that contains an entry with data descriptor (i.e., its compressed size is not known in advance).
#
# @TEST-EXEC: zeek -r ${TRACES}/zip/test.pcap frameworks/files/extract-all-files frameworks/files/hash-all-files %INPUT
# @TEST-EXEC: for i in extract_files/*; do (printf "$i "; wc -c "$i" | awk '{print $1}'); done | sort >extracted.log
# @TEST-EXEC: for i in files.log extracted.log .stdout; do cat $i | sed 's#\(extract-[^-]*\)-[^-]*-#\1-xxx-#g' | sed 's#F[A-Za-z0-9]\{16,17\}#XXXXXXXXXXXXXXXXX#g' >$i.tmp && mv $i.tmp $i; done
#
# @TEST-EXEC: btest-diff-cut -m uid fuid mime_type source filename extracted extracted_size ftime files.log
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff extracted.log

@load base/files/zip

event ZIP::file(f: fa_file, zip_file: ZIP::File)
	{
	print zip_file;
	}

event ZIP::end_of_directory(f: fa_file, comment: string)
	{
	print comment;
	}
