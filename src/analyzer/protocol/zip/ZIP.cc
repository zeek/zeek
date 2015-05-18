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

	// "32" is a gross overload hack that means "check it 
	// for whether it's a gzip file".  Sheesh.
	if ( inflateInit2(zip, MAX_WBITS+32) != Z_OK )
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
	int allow_restart = 1;
	u_char *unzipbuf = new u_char[unzip_size];
	if ( unzipbuf == NULL )
		{
		Weird("failed_to_allocate_deflate_buffer");
		return;
		}

	zip->next_in = (Bytef*) data;
	zip->avail_in = len;

	Bytef *orig_in = zip->next_in;
	size_t nread = zip->avail_in;

	for(;;)
		{
		zip->next_out = (Bytef *)unzipbuf;
		zip->avail_out = unzip_size;

		zip_status = inflate(zip, Z_SYNC_FLUSH);
		if ( zip_status == Z_STREAM_END ||
		     zip_status == Z_OK )
			{
			allow_restart = 0;

			int have = unzip_size - zip->avail_out;
			if ( have )
				ForwardStream(have, unzipbuf, IsOrig());

			if ( zip_status == Z_STREAM_END )
				{
				inflateEnd(zip);
				delete unzipbuf;
				return;
				}

			if ( zip->avail_in == 0 )
				{
				delete unzipbuf;
				return;
				}
			}
		else if ( allow_restart && zip_status == Z_DATA_ERROR )
			{
			// Some servers seem to not generate zlib headers, 
			// so this is an attempt to fix and continue anyway.
			inflateEnd(zip);
			if ( inflateInit2(zip, -MAX_WBITS) != Z_OK ) 
				{
				delete unzipbuf;
				return;
				}

			zip->next_in = orig_in;
			zip->avail_in = nread;
			allow_restart = 0;
			continue;
			}
		else
			{
			Weird("inflate_failed");
			delete unzipbuf;
			return;
			}
		}
	}
