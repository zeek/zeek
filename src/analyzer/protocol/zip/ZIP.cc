// See the file "COPYING" in the main distribution directory for copyright.

#include "ZIP.h"

using namespace analyzer::zip;

ZIP_Analyzer::ZIP_Analyzer(zeek::Connection* conn, bool orig, Method arg_method)
: zeek::analyzer::tcp::TCP_SupportAnalyzer("ZIP", conn, orig)
	{
	zip = nullptr;
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
	if ( inflateInit2(zip, MAX_WBITS + 32) != Z_OK )
		{
		Weird("inflate_init_failed");
		delete zip;
		zip = nullptr;
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
	zeek::analyzer::tcp::TCP_SupportAnalyzer::DeliverStream(len, data, orig);

	if ( ! len || zip_status != Z_OK )
		return;

	static unsigned int unzip_size = 4096;
	auto unzipbuf = std::make_unique<Bytef[]>(unzip_size);

	int allow_restart = 1;

	zip->next_in = (Bytef*) data;
	zip->avail_in = len;

	Bytef *orig_next_in = zip->next_in;
	size_t orig_avail_in = zip->avail_in;

	while ( true )
		{
		zip->next_out = unzipbuf.get();
		zip->avail_out = unzip_size;

		zip_status = inflate(zip, Z_SYNC_FLUSH);

		if ( zip_status == Z_STREAM_END ||
		     zip_status == Z_OK )
			{
			allow_restart = 0;

			int have = unzip_size - zip->avail_out;
			if ( have )
				ForwardStream(have, unzipbuf.get(), IsOrig());

			if ( zip_status == Z_STREAM_END )
				{
				inflateEnd(zip);
				return;
				}

			if ( zip->avail_in == 0 )
				return;

			}

		else if ( allow_restart && zip_status == Z_DATA_ERROR )
			{
			// Some servers seem to not generate zlib headers,
			// so this is an attempt to fix and continue anyway.
			inflateEnd(zip);

			if ( inflateInit2(zip, -MAX_WBITS) != Z_OK )
				{
				Weird("inflate_init_failed");
				return;
				}

			zip->next_in = orig_next_in;
			zip->avail_in = orig_avail_in;
			allow_restart = 0;
			continue;
			}

		else
			{
			Weird("inflate_failed");
			return;
			}
		}
	}
