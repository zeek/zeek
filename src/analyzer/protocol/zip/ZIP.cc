// See the file "COPYING" in the main distribution directory for copyright.

#include "ZIP.h"

#include "events.bif.h"

using namespace analyzer::zip;

ZIP_Analyzer::ZIP_Analyzer(Connection* conn, bool orig, Method arg_method)
: tcp::TCP_SupportAnalyzer("ZIP", conn, orig)
	{
	zip = 0;
	zip_status = Z_OK;
	method = arg_method;

	zip = new z_stream;
	zip->zalloc = 0;
	zip->zfree = 0;
	zip->opaque = 0;
	zip->next_out = 0;
	zip->avail_out = 0;
	zip->next_in = 0;
	zip->avail_in = 0;

	// "15" here means maximum compression.  "32" is a gross overload
	// hack that means "check it for whether it's a gzip file".  Sheesh.
	zip_status = inflateInit2(zip, 15 + 32);
	if ( zip_status != Z_OK )
		{
		Weird("inflate_init_failed");
		delete zip;
		zip = 0;
		}
	}

ZIP_Analyzer::~ZIP_Analyzer()
	{
	delete zip;
	}

void ZIP_Analyzer::Done()
	{
	Analyzer::Done();

	if ( zip )
		inflateEnd(zip);
	}

void ZIP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	tcp::TCP_SupportAnalyzer::DeliverStream(len, data, orig);

	if ( ! len || zip_status != Z_OK )
		return;

	static unsigned int unzip_size = 4096;
	Bytef unzipbuf[unzip_size];

	zip->next_in = (Bytef*) data;
	zip->avail_in = len;

	do
		{
		zip->next_out = unzipbuf;
		zip->avail_out = unzip_size;

		zip_status = inflate(zip, Z_SYNC_FLUSH);

		if ( zip_status != Z_STREAM_END &&
		     zip_status != Z_OK &&
		     zip_status != Z_BUF_ERROR )
			{
			Weird("inflate_failed");
			inflateEnd(zip);
			break;
			}

		int have = unzip_size - zip->avail_out;
		if ( have )
			ForwardStream(have, unzipbuf, IsOrig());

		if ( zip_status == Z_STREAM_END )
			{
			inflateEnd(zip);
			delete zip;
			zip = 0;
			break;
			}

		zip_status = Z_OK;
		}
	while ( zip->avail_out == 0 );
	}
