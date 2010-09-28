// $Id: FileAnalyzer.cc,v 1.1.4.2 2006/06/01 17:18:10 sommer Exp $

#include "FileAnalyzer.h"

#ifdef HAVE_LIBMAGIC
magic_t File_Analyzer::magic = 0;
magic_t File_Analyzer::magic_mime = 0;
#endif

#ifdef HAVE_LIBCLAMAV
struct cl_node* File_Analyzer::clam_root = 0;
#endif

File_Analyzer::File_Analyzer(Connection* conn)
: TCP_ApplicationAnalyzer(AnalyzerTag::File, conn)
	{
	buffer_len = 0;

#ifdef HAVE_LIBMAGIC
	if ( ! magic )
		{
		InitMagic(&magic, MAGIC_NONE);
		InitMagic(&magic_mime, MAGIC_MIME);
		}
#endif

#ifdef HAVE_LIBCLAMAV
	if ( ! clam_root )
		InitClamAV();
#endif
	}

void File_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	int n = min(len, BUFFER_SIZE - buffer_len);

	if ( n )
		{
		strncpy(buffer + buffer_len, (const char*) data, n);
		buffer_len += n;

		if ( buffer_len == BUFFER_SIZE )
			Identify();
		}
	return;
	}

void File_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	if ( buffer_len && buffer_len != BUFFER_SIZE )
		Identify();
	}

void File_Analyzer::Identify()
	{
	const char* descr = 0;
	const char* mime = 0;

#ifdef HAVE_LIBMAGIC
	if ( magic )
		descr = magic_buffer(magic, buffer, buffer_len);

	if ( magic_mime )
		mime = magic_buffer(magic_mime, buffer, buffer_len);
#endif

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(new StringVal(buffer_len, buffer));
	vl->append(new StringVal(descr ? descr : "<unknown>"));
	vl->append(new StringVal(mime ? mime : "<unknown>"));
	ConnectionEvent(file_transferred, vl);

#ifdef HAVE_LIBCLAMAV
	const char* virname;
	int ret = cl_scanbuff(buffer, buffer_len, &virname, clam_root);

	if ( ret == CL_VIRUS )
		{
		val_list* vl = new val_list;
		vl->append(BuildConnVal());
		vl->append(new StringVal(virname));
		ConnectionEvent(file_virus, vl);
		}
#endif
	}

#ifdef HAVE_LIBMAGIC
void File_Analyzer::InitMagic(magic_t* magic, int flags)
	{
	*magic = magic_open(flags);

	if ( ! *magic )
		error(fmt("can't init libmagic: %s", magic_error(*magic)));

	else if ( magic_load(*magic, 0) < 0 )
		{
		error(fmt("can't load magic file: %s", magic_error(*magic)));
		magic_close(*magic);
		*magic = 0;
		}
	}
#endif

#ifdef HAVE_LIBCLAMAV
void File_Analyzer::InitClamAV()
	{
	unsigned int sigs;
	int ret = cl_loaddbdir(cl_retdbdir(), &clam_root, &sigs);

	if ( ret )
		{
		error(fmt("can't load ClamAV database: %s", cl_perror(ret)));
		clam_root = 0;
		return;
		}

	ret = cl_build(clam_root);
	if ( ret )
		{
		error(fmt("can't init ClamAV database: %s", cl_perror(ret)));
		cl_free(clam_root);
		clam_root = 0;
		return;
		}
	}
#endif
