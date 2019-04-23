#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <algorithm>

#include "zeek-config.h"
#include "ChunkedIO.h"
#include "NetVar.h"
#include "RemoteSerializer.h"

ChunkedIO::ChunkedIO() : stats(), tag(), pure()
	{
	}

void ChunkedIO::Stats(char* buffer, int length)
	{
	safe_snprintf(buffer, length,
		      "bytes=%luK/%luK chunks=%lu/%lu io=%lu/%lu bytes/io=%.2fK/%.2fK",
		      stats.bytes_read / 1024, stats.bytes_written / 1024,
		      stats.chunks_read, stats.chunks_written,
		      stats.reads, stats.writes,
		      stats.bytes_read / (1024.0 * stats.reads),
		      stats.bytes_written / (1024.0 * stats.writes));
	}

#ifdef DEBUG_COMMUNICATION

void ChunkedIO::AddToBuffer(uint32 len, char* data, bool is_read)
	{
	Chunk* copy = new Chunk;
	copy->len = len;
	copy->data = new char[len];
	memcpy(copy->data, data, len);

	std::list<Chunk*>* l = is_read ? &data_read : &data_written;
	l->push_back(copy);

	if ( l->size() > DEBUG_COMMUNICATION )
		{
		Chunk* old = l->front();
		l->pop_front();
		delete [] old->data;
		delete old;
		}
	}

void ChunkedIO::AddToBuffer(Chunk* chunk, bool is_read)
	{
	AddToBuffer(chunk->len, chunk->data, is_read);
	}

void ChunkedIO::DumpDebugData(const char* basefnname, bool want_reads)
	{
	std::list<Chunk*>* l = want_reads ? &data_read : &data_written;

	int count = 0;

	for ( std::list<Chunk*>::iterator i = l->begin(); i != l->end(); ++i )
		{
		static char buffer[128];
		snprintf(buffer, sizeof(buffer), "%s.%s.%d", basefnname,
				 want_reads ? "read" : "write", ++count);
		buffer[sizeof(buffer) - 1] = '\0';

		int fd = open(buffer, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if ( fd < 0 )
			continue;

		ChunkedIOFd io(fd, "dump-file");
		io.Write(*i);
		io.Flush();
		safe_close(fd);
		}

	l->clear();
	}

#endif

ChunkedIOFd::ChunkedIOFd(int arg_fd, const char* arg_tag, pid_t arg_pid)
	{
	int flags;

	tag = arg_tag;
	fd = arg_fd;
	eof = 0;
	last_flush = current_time();
	failed_reads = 0;

	if ( (flags = fcntl(fd, F_GETFL, 0)) < 0)
		{
		Log(fmt("can't obtain socket flags: %s", strerror(errno)));
		exit(1);
		}

	if ( fcntl(fd, F_SETFL, flags|O_NONBLOCK) < 0 )
		{
		Log(fmt("can't set fd to non-blocking: %s (%d)",
			  strerror(errno), getpid()));
		exit(1);
		}

	read_buffer = new char[BUFFER_SIZE];
	read_len = 0;
	read_pos = 0;
	partial = 0;
	write_buffer = new char[BUFFER_SIZE];
	write_len = 0;
	write_pos = 0;

	pending_head = 0;
	pending_tail = 0;

	pid = arg_pid;
	}

ChunkedIOFd::~ChunkedIOFd()
	{
	Clear();

	delete [] read_buffer;
	delete [] write_buffer;
	safe_close(fd);
	delete partial;
	}

bool ChunkedIOFd::Write(Chunk* chunk)
	{
#ifdef DEBUG
	DBG_LOG(DBG_CHUNKEDIO, "write of size %d [%s]",
		chunk->len, fmt_bytes(chunk->data, min((uint32)20, chunk->len)));
#endif

#ifdef DEBUG_COMMUNICATION
	AddToBuffer(chunk, false);
#endif

	if ( chunk->len <= BUFFER_SIZE - sizeof(uint32) )
		return WriteChunk(chunk, false);

	// We have to split it up.
	char* p = chunk->data;
	uint32 left = chunk->len;

	while ( left )
		{
		uint32 sz = min<uint32>(BUFFER_SIZE - sizeof(uint32), left);
		Chunk* part = new Chunk(new char[sz], sz);

		memcpy(part->data, p, part->len);
		left -= part->len;
		p += part->len;

		if ( ! WriteChunk(part, left != 0) )
			return false;
		}

	delete chunk;
	return true;
	}

bool ChunkedIOFd::WriteChunk(Chunk* chunk, bool partial)
	{
	assert(chunk->len <= BUFFER_SIZE - sizeof(uint32) );

	if ( chunk->len == 0 )
		InternalError("attempt to write 0 bytes chunk");

	if ( partial )
		chunk->len |= FLAG_PARTIAL;

	++stats.chunks_written;

	// If it fits into the buffer, we're done (but keep care not
	// to reorder chunks).
	if ( ! pending_head && PutIntoWriteBuffer(chunk) )
		return true;

	// Otherwise queue it.
	++stats.pending;
	ChunkQueue* q = new ChunkQueue;
	q->chunk = chunk;
	q->next = 0;

	if ( pending_tail )
		{
		pending_tail->next = q;
		pending_tail = q;
		}
	else
		pending_head = pending_tail = q;

	write_flare.Fire();
	return Flush();
	}


bool ChunkedIOFd::PutIntoWriteBuffer(Chunk* chunk)
	{
	uint32 len = chunk->len & ~FLAG_PARTIAL;

	if ( write_len + len + (IsPure() ? 0 : sizeof(len)) > BUFFER_SIZE )
		return false;

	if ( ! IsPure() )
		{
		uint32 nlen = htonl(chunk->len);
		memcpy(write_buffer + write_len, &nlen, sizeof(nlen));
		write_len += sizeof(nlen);
		}

	memcpy(write_buffer + write_len, chunk->data, len);
	write_len += len;

	delete chunk;
	write_flare.Fire();

	if ( network_time - last_flush > 0.005 )
		FlushWriteBuffer();

	return true;
	}

bool ChunkedIOFd::FlushWriteBuffer()
	{
	last_flush = network_time;

	while ( write_pos != write_len )
		{
		uint32 len = write_len - write_pos;

		int written = write(fd, write_buffer + write_pos, len);

		if ( written < 0 )
			{
			if ( errno == EPIPE )
				eof = true;

			if ( errno != EINTR )
				// These errnos are equal on POSIX.
				return errno == EWOULDBLOCK || errno == EAGAIN;

			else
				written = 0;
			}

		stats.bytes_written += written;
		if ( written > 0 )
			++stats.writes;

		if ( unsigned(written) == len )
			{
			write_pos = write_len = 0;

			if ( ! pending_head )
				write_flare.Extinguish();

			return true;
			}

		if ( written == 0 )
			InternalError("written==0");

		// Short write.
		write_pos += written;
		}

	return true;
	}

bool ChunkedIOFd::OptionalFlush()
	{
	// This threshhold is quite arbitrary.
//	if ( current_time() - last_flush > 0.01 )
	return Flush();
	}

bool ChunkedIOFd::Flush()
	{
	// Try to write data out.
	while ( pending_head )
		{
		if ( ! FlushWriteBuffer() )
			return false;

		// If we couldn't write the whole buffer, we stop here
		// and try again next time.
		if ( write_len > 0 )
			return true;

		// Put as many pending chunks into the buffer as possible.
		while ( pending_head )
			{
			if ( ! PutIntoWriteBuffer(pending_head->chunk) )
				break;

			ChunkQueue* q = pending_head;
			pending_head = pending_head->next;
			if ( ! pending_head )
				pending_tail = 0;

			--stats.pending;
			delete q;
			}
		}

	bool rval = FlushWriteBuffer();

	if ( ! pending_head && write_len == 0 )
		write_flare.Extinguish();

	return rval;
	}

uint32 ChunkedIOFd::ChunkAvailable()
	{
	int bytes_left = read_len - read_pos;

	if ( bytes_left < int(sizeof(uint32)) )
		return 0;

	bytes_left -= sizeof(uint32);

	// We have to copy the value here as it may not be
	// aligned correctly in the data.
	uint32 len;
	memcpy(&len, read_buffer + read_pos, sizeof(len));
	len = ntohl(len);

	if ( uint32(bytes_left) < (len & ~FLAG_PARTIAL) )
		return 0;

	assert(len & ~FLAG_PARTIAL);

	return len;
	}

ChunkedIO::Chunk* ChunkedIOFd::ExtractChunk()
	{
	uint32 len = ChunkAvailable();
	uint32 real_len = len & ~FLAG_PARTIAL;
	if ( ! real_len )
		return 0;

	read_pos += sizeof(uint32);

	Chunk* chunk = new Chunk(new char[real_len], len);
	memcpy(chunk->data, read_buffer + read_pos, real_len);
	read_pos += real_len;

	++stats.chunks_read;

	return chunk;
	}

ChunkedIO::Chunk* ChunkedIOFd::ConcatChunks(Chunk* c1, Chunk* c2)
	{
	uint32 sz = c1->len + c2->len;
	Chunk* c = new Chunk(new char[sz], sz);

	memcpy(c->data, c1->data, c1->len);
	memcpy(c->data + c1->len, c2->data, c2->len);

	delete c1;
	delete c2;

	return c;
	}

void ChunkedIO::Log(const char* str)
	{
	RemoteSerializer::Log(RemoteSerializer::LogError, str);
	}

bool ChunkedIOFd::Read(Chunk** chunk, bool may_block)
	{
	*chunk = 0;

	// We will be called regularly. So take the opportunity
	// to flush the write buffer once in a while.
	OptionalFlush();

	if ( ! ReadChunk(chunk, may_block) )
		{
#ifdef DEBUG_COMMUNICATION
		AddToBuffer("<false:read-chunk>", true);
#endif
		if ( ! ChunkAvailable() )
			read_flare.Extinguish();

		return false;
		}

	if ( ! *chunk )
		{
#ifdef DEBUG_COMMUNICATION
		AddToBuffer("<null:no-data>", true);
#endif
		read_flare.Extinguish();
		return true;
		}

	if ( ChunkAvailable() )
		read_flare.Fire();
	else
		read_flare.Extinguish();

#ifdef DEBUG
	if ( *chunk )
		DBG_LOG(DBG_CHUNKEDIO, "read of size %d %s[%s]",
				(*chunk)->len & ~FLAG_PARTIAL,
				(*chunk)->len & FLAG_PARTIAL ? "(P) " : "",
				fmt_bytes((*chunk)->data,
						min((uint32)20, (*chunk)->len)));
#endif

	if ( ! ((*chunk)->len & FLAG_PARTIAL) )
		{
		if ( ! partial )
			{
#ifdef DEBUG_COMMUNICATION
			AddToBuffer(*chunk, true);
#endif
			return true;
			}
		else
			{
			// This is the last chunk of an oversized one.
			*chunk = ConcatChunks(partial, *chunk);
			partial = 0;

#ifdef DEBUG
			if ( *chunk )
				DBG_LOG(DBG_CHUNKEDIO,
					"built virtual chunk of size %d [%s]",
					(*chunk)->len,
					fmt_bytes((*chunk)->data, 20));
#endif

#ifdef DEBUG_COMMUNICATION
			AddToBuffer(*chunk, true);
#endif
			return true;
			}
		}

	// This chunk is the non-last part of an oversized.
	(*chunk)->len &= ~FLAG_PARTIAL;

	if ( ! partial )
		// First part of oversized chunk.
		partial = *chunk;
	else
		partial = ConcatChunks(partial, *chunk);

#ifdef DEBUG_COMMUNICATION
	AddToBuffer("<null:partial>", true);
#endif

	*chunk = 0;
	return true; // Read following part next time.
	}

bool ChunkedIOFd::ReadChunk(Chunk** chunk, bool may_block)
	{
	// We will be called regularly. So take the opportunity
	// to flush the write buffer once in a while.
	OptionalFlush();

	*chunk = ExtractChunk();
	if ( *chunk )
		return true;

	int bytes_left = read_len - read_pos;

	// If we have a partial chunk left, move this to the head of
	// the buffer.
	if ( bytes_left )
		memmove(read_buffer, read_buffer + read_pos, bytes_left);

	read_pos = 0;
	read_len = bytes_left;

	if ( ! ChunkAvailable() )
		read_flare.Extinguish();

	// If allowed, wait a bit for something to read.
	if ( may_block )
		{
		fd_set fd_read, fd_write, fd_except;

		FD_ZERO(&fd_read);
		FD_ZERO(&fd_write);
		FD_ZERO(&fd_except);
		FD_SET(fd, &fd_read);

		struct timeval small_timeout;
		small_timeout.tv_sec = 0;
		small_timeout.tv_usec = 50;

		select(fd + 1, &fd_read, &fd_write, &fd_except, &small_timeout);
		}

	// Make sure the process is still runnning
	// (only checking for EPIPE after a read doesn't
	// seem to be sufficient).
	if ( pid && kill(pid, 0) < 0 && errno != EPERM )
		{
		eof = true;
		errno = EPIPE;
		return false;
		}

	// Try to fill the buffer.
	while ( true )
		{
		int len = BUFFER_SIZE - read_len;
		int read = ::read(fd, read_buffer + read_len, len);

		if ( read < 0 )
			{
			if ( errno != EINTR )
				{
				// These errnos are equal on POSIX.
				if ( errno == EWOULDBLOCK || errno == EAGAIN )
					{
					// Let's see if we have a chunk now --
					// even if we time out, we may have read
					// just enough in previous iterations!
					*chunk = ExtractChunk();
					++failed_reads;
					return true;
					}

				if ( errno == EPIPE )
					eof = true;

				return false;
				}

			else
				read = 0;
			}

		failed_reads = 0;

		if ( read == 0 && len != 0 )
			{
			*chunk = ExtractChunk();
			if ( *chunk )
				return true;

			eof = true;
			return false;
			}

		read_len += read;

		++stats.reads;
		stats.bytes_read += read;

		if ( read == len )
			break;
		}

	// Let's see if we have a chunk now.
	*chunk = ExtractChunk();

	return true;
	}

bool ChunkedIOFd::CanRead()
	{
	// We will be called regularly. So take the opportunity
	// to flush the write buffer once in a while.
	OptionalFlush();

	if ( ChunkAvailable() )
		return true;

	fd_set fd_read;
	FD_ZERO(&fd_read);
	FD_SET(fd, &fd_read);

	struct timeval no_timeout;
	no_timeout.tv_sec = 0;
	no_timeout.tv_usec = 0;

	return select(fd + 1, &fd_read, 0, 0, &no_timeout) > 0;
	}

bool ChunkedIOFd::CanWrite()
	{
	return pending_head != 0;
	}

bool ChunkedIOFd::IsIdle()
	{
	if ( pending_head || ChunkAvailable() )
		return false;

	if ( failed_reads > 0 )
		return true;

	return false;
	}

bool ChunkedIOFd::IsFillingUp()
	{
	return stats.pending > chunked_io_buffer_soft_cap;
	}

iosource::FD_Set ChunkedIOFd::ExtraReadFDs() const
	{
	iosource::FD_Set rval;
	rval.Insert(write_flare.FD());
	rval.Insert(read_flare.FD());
	return rval;
	}

void ChunkedIOFd::Clear()
	{
	while ( pending_head )
		{
		ChunkQueue* next = pending_head->next;
		delete pending_head->chunk;
		delete pending_head;
		pending_head = next;
		}

	pending_head = pending_tail = 0;

	if ( write_len == 0 )
		write_flare.Extinguish();
	}

const char* ChunkedIOFd::Error()
	{
	static char buffer[1024];
	safe_snprintf(buffer, sizeof(buffer), "%s [%d]", strerror(errno), errno);

	return buffer;
	}

void ChunkedIOFd::Stats(char* buffer, int length)
	{
	int i = safe_snprintf(buffer, length, "pending=%d ", stats.pending);
	ChunkedIO::Stats(buffer + i, length - i);
	}

SSL_CTX* ChunkedIOSSL::ctx;

ChunkedIOSSL::ChunkedIOSSL(int arg_socket, bool arg_server)
	{
	socket = arg_socket;
	last_ret = 0;
	eof = false;
	setup = false;
	server = arg_server;
	ssl = 0;

	write_state = LEN;
	write_head = 0;
	write_tail = 0;

	read_state = LEN;
	read_chunk = 0;
	read_ptr = 0;
	}

ChunkedIOSSL::~ChunkedIOSSL()
	{
	if ( setup )
		{
		SSL_shutdown(ssl);

		// We don't care if the other side closes properly.
		setup = false;
		}

	if ( ssl )
		{
		SSL_free(ssl);
		ssl = 0;
		}

	safe_close(socket);
	}


static int pem_passwd_cb(char* buf, int size, int rwflag, void* passphrase)
	{
	safe_strncpy(buf, (char*) passphrase, size);
	buf[size - 1] = '\0';
	return strlen(buf);
	}

bool ChunkedIOSSL::Init()
	{
	// If the handshake doesn't succeed immediately we will
	// be called multiple times.
	if ( ! ctx )
		{
		SSL_load_error_strings();

		ctx = SSL_CTX_new(SSLv23_method());
		if ( ! ctx )
			{
			Log("can't create SSL context");
			return false;
			}

		// We access global variables here. But as they are
		// declared const and we don't modify them this should
		// be fine.
		const char* key = ssl_private_key->AsString()->CheckString();

		if ( ! (key && *key &&
			SSL_CTX_use_certificate_chain_file(ctx, key)) )
			{
			Log(fmt("can't read certificate from file %s", key));
			return false;
			}

		const char* passphrase =
			ssl_passphrase->AsString()->CheckString();

		if ( passphrase && ! streq(passphrase, "<undefined>") )
			{
			SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
			SSL_CTX_set_default_passwd_cb_userdata(ctx,
							(void*) passphrase);
			}

		if ( ! (key && *key &&
			SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM)) )
			{
			Log(fmt("can't read private key from file %s", key));
			return false;
			}

		const char* ca = ssl_ca_certificate->AsString()->CheckString();
		if ( ! (ca && *ca && SSL_CTX_load_verify_locations(ctx, ca, 0)) )
			{
			Log(fmt("can't read CA certificate from file %s", ca));
			return false;
			}

		// Only use real ciphers.
		if ( ! SSL_CTX_set_cipher_list(ctx, "HIGH") )
			{
			Log("can't set cipher list");
			return false;
			}

		// Require client certificate.
		SSL_CTX_set_verify(ctx,
			SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
		}

	int flags;

	if ( (flags = fcntl(socket, F_GETFL, 0)) < 0)
		{
		Log(fmt("can't obtain socket flags: %s", strerror(errno)));
		return false;
		}

	if ( fcntl(socket, F_SETFL, flags|O_NONBLOCK) < 0 )
		{
		Log(fmt("can't set socket to non-blocking: %s",
			  strerror(errno)));
		return false;
		}

	if ( ! ssl )
		{
		ssl = SSL_new(ctx);
		if ( ! ssl )
			{
			Log("can't create SSL object");
			return false;
			}

		BIO* bio = BIO_new_socket(socket, BIO_NOCLOSE);
		BIO_set_nbio(bio, 1);
		SSL_set_bio(ssl, bio, bio);
		}

	int success;
	if ( server )
		success = last_ret = SSL_accept(ssl);
	else
		success = last_ret = SSL_connect(ssl);

	if ( success > 0 )
		{ // handshake done
		setup = true;
		return true;
		}

	int error = SSL_get_error(ssl, success);

	if ( success <= 0 &&
	     (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) )
		// Handshake not finished yet, but that's ok for now.
		return true;

	// Some error.
	eof = true;
	return false;
	}

bool ChunkedIOSSL::Write(Chunk* chunk)
	{
#ifdef DEBUG
	DBG_LOG(DBG_CHUNKEDIO, "ssl write of size %d [%s]",
		chunk->len, fmt_bytes(chunk->data, 20));
#endif

	// Queue it.
	++stats.pending;
	Queue* q = new Queue;
	q->chunk = chunk;
	q->next = 0;

	// Temporarily convert len into network byte order.
	chunk->len = htonl(chunk->len);

	if ( write_tail )
		{
		write_tail->next = q;
		write_tail = q;
		}
	else
		write_head = write_tail = q;

	write_flare.Fire();
	Flush();
	return true;
	}

bool ChunkedIOSSL::WriteData(char* p, uint32 len, bool* error)
	{
	*error = false;

	double t = current_time();

	int written = last_ret = SSL_write(ssl, p, len);

	switch ( SSL_get_error(ssl, written) ) {
		case SSL_ERROR_NONE:
			// SSL guarantees us that all bytes have been written.
			// That's nice. :-)
			return true;

		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			// Would block.
			DBG_LOG(DBG_CHUNKEDIO,
				"SSL_write: SSL_ERROR_WANT_READ [%d,%d]",
				written, SSL_get_error(ssl, written));
			*error = false;
			return false;

		case SSL_ERROR_ZERO_RETURN:
			// Regular remote connection shutdown.
			DBG_LOG(DBG_CHUNKEDIO,
				"SSL_write: SSL_ZERO_RETURN [%d,%d]",
				written, SSL_get_error(ssl, written));
			*error = eof = true;
			return false;

		case SSL_ERROR_SYSCALL:
			DBG_LOG(DBG_CHUNKEDIO,
				"SSL_write: SSL_SYS_CALL [%d,%d]",
				written, SSL_get_error(ssl, written));

			if ( written == 0 )
				{
				// Socket connection closed.
				*error = eof = true;
				return false;
				}

			// Fall through.

		default:
			DBG_LOG(DBG_CHUNKEDIO,
				"SSL_write: fatal error [%d,%d]",
				written, SSL_get_error(ssl, written));
			// Fatal SSL error.
			*error = true;
			return false;
	}

	InternalError("can't be reached");
	return false;
	}

bool ChunkedIOSSL::Flush()
	{
	if ( ! setup )
		{
		// We may need to finish the handshake.
		if ( ! Init() )
			return false;
		if ( ! setup )
			return true;
		}

	while ( write_head )
		{
		bool error;

		Chunk* c = write_head->chunk;

		if ( write_state == LEN )
			{
			if ( ! WriteData((char*)&c->len, sizeof(c->len), &error) )
				return ! error;
			write_state = DATA;

			// Convert back from network byte order.
			c->len = ntohl(c->len);
			}

		if ( ! WriteData(c->data, c->len, &error) )
			return ! error;

		// Chunk written, throw away.
		Queue* q = write_head;
		write_head = write_head->next;
		if ( ! write_head )
			write_tail = 0;
		--stats.pending;
		delete q;

		delete c;

		write_state = LEN;
		}

	write_flare.Extinguish();
	return true;
	}

bool ChunkedIOSSL::ReadData(char* p, uint32 len, bool* error)
	{
	if ( ! read_ptr )
		read_ptr = p;

	while ( true )
		{
		double t = current_time();

		int read = last_ret =
			SSL_read(ssl, read_ptr, len - (read_ptr - p));

		switch ( SSL_get_error(ssl, read) ) {
		case SSL_ERROR_NONE:
			// We're fine.
			read_ptr += read;

			if ( unsigned(read_ptr - p) == len )
				{
				// We have read as much as requested..
				read_ptr = 0;
				*error = false;
				return true;
				}

			break;

		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			// Would block.
			DBG_LOG(DBG_CHUNKEDIO,
				"SSL_read: SSL_ERROR_WANT_READ [%d,%d]",
				read, SSL_get_error(ssl, read));
			*error = false;
			return false;

		case SSL_ERROR_ZERO_RETURN:
			// Regular remote connection shutdown.
			DBG_LOG(DBG_CHUNKEDIO,
				"SSL_read: SSL_ZERO_RETURN [%d,%d]",
				read, SSL_get_error(ssl, read));
			*error = eof = true;
			return false;

		case SSL_ERROR_SYSCALL:
			DBG_LOG(DBG_CHUNKEDIO, "SSL_read: SSL_SYS_CALL [%d,%d]",
				read, SSL_get_error(ssl, read));

			if ( read == 0 )
				{
				// Socket connection closed.
				*error = eof = true;
				return false;
				}

			// Fall through.

		default:
			DBG_LOG(DBG_CHUNKEDIO,
				"SSL_read: fatal error [%d,%d]",
				read, SSL_get_error(ssl, read));

			// Fatal SSL error.
			*error = true;
			return false;
		}
		}

	// Can't be reached.
	InternalError("can't be reached");
	return false;
	}

bool ChunkedIOSSL::Read(Chunk** chunk, bool mayblock)
	{
	*chunk = 0;

	if ( ! setup )
		{
		// We may need to finish the handshake.
		if ( ! Init() )
			return false;
		if ( ! setup )
			return true;
		}

	bool error;

	Flush();

	if ( read_state == LEN )
		{
		if ( ! read_chunk )
			{
			read_chunk = new Chunk;
			read_chunk->data = 0;
			}

		if ( ! ReadData((char*)&read_chunk->len,
				sizeof(read_chunk->len),
				&error) )
			return ! error;

		read_state = DATA;
		read_chunk->len = ntohl(read_chunk->len);
		}

	if ( ! read_chunk->data )
		{
		read_chunk->data = new char[read_chunk->len];
		read_chunk->free_func = Chunk::free_func_delete;
		}

	if ( ! ReadData(read_chunk->data, read_chunk->len, &error) )
		return ! error;

	// Chunk fully read. Pass it on.
	*chunk = read_chunk;
	read_chunk = 0;
	read_state = LEN;

#ifdef DEBUG
	DBG_LOG(DBG_CHUNKEDIO, "ssl read of size %d [%s]",
		(*chunk)->len, fmt_bytes((*chunk)->data, 20));
#endif

	return true;
	}

bool ChunkedIOSSL::CanRead()
	{
	// We will be called regularly. So take the opportunity
	// to flush the write buffer.
	Flush();

	if ( SSL_pending(ssl) )
		return true;

	fd_set fd_read;
	FD_ZERO(&fd_read);
	FD_SET(socket, &fd_read);

	struct timeval notimeout;
	notimeout.tv_sec = 0;
	notimeout.tv_usec = 0;

	return select(socket + 1, &fd_read, NULL, NULL, &notimeout) > 0;
	}

bool ChunkedIOSSL::CanWrite()
	{
	return write_head != 0;
	}

bool ChunkedIOSSL::IsIdle()
	{
	return ! (CanRead() || CanWrite());
	}

bool ChunkedIOSSL::IsFillingUp()
	{
	// We don't really need this at the moment (since SSL is only used for
	// peer-to-peer communication). Thus, we always return false for now.
	return false;
	}

iosource::FD_Set ChunkedIOSSL::ExtraReadFDs() const
	{
	iosource::FD_Set rval;
	rval.Insert(write_flare.FD());
	return rval;
	}

void ChunkedIOSSL::Clear()
	{
	while ( write_head )
		{
		Queue* next = write_head->next;
		delete write_head->chunk;
		delete write_head;
		write_head = next;
		}
	write_head = write_tail = 0;
	write_flare.Extinguish();
	}

const char* ChunkedIOSSL::Error()
	{
	const int BUFLEN = 512;
	static char buffer[BUFLEN];

	int sslcode = SSL_get_error(ssl, last_ret);
	int errcode = ERR_get_error();

	int count = safe_snprintf(buffer, BUFLEN, "[%d,%d,%d] SSL error: ",
					errcode, sslcode, last_ret);

	if ( errcode )
		ERR_error_string_n(errcode, buffer + count, BUFLEN - count);

	else if ( sslcode == SSL_ERROR_SYSCALL )
		{
		if ( last_ret )
			// Look at errno.
			safe_snprintf(buffer + count, BUFLEN - count,
					"syscall: %s", strerror(errno));
		else
			// Errno is not valid in this case.
			safe_strncpy(buffer + count,
					"syscall: unexpected end-of-file",
					BUFLEN - count);
		}
	else
		safe_strncpy(buffer + count, "unknown error", BUFLEN - count);

	return buffer;
	}

void ChunkedIOSSL::Stats(char* buffer, int length)
	{
	int i = safe_snprintf(buffer, length, "pending=%ld ", stats.pending);
	ChunkedIO::Stats(buffer + i, length - i);
	}

bool CompressedChunkedIO::Init()
	{
	zin.zalloc = 0;
	zin.zfree = 0;
	zin.opaque = 0;

	zout.zalloc = 0;
	zout.zfree = 0;
	zout.opaque = 0;

	compress = uncompress = false;
	error = 0;
	uncompressed_bytes_read	= 0;
	uncompressed_bytes_written = 0;

	return true;
	}

bool CompressedChunkedIO::Read(Chunk** chunk, bool may_block)
	{
	if ( ! io->Read(chunk, may_block) )
		return false;

	if ( ! uncompress )
		return true;

	if ( ! *chunk )
		return true;

	uint32 uncompressed_len =
		*(uint32*)((*chunk)->data + (*chunk)->len - sizeof(uint32));

	if ( uncompressed_len == 0 )
		{
		// Not compressed.
		DBG_LOG(DBG_CHUNKEDIO, "zlib read pass-through: size=%d",
			(*chunk)->len);
		return true;
		}

	char* uncompressed = new char[uncompressed_len];

	DBG_LOG(DBG_CHUNKEDIO, "zlib read: size=%d uncompressed=%d",
		(*chunk)->len, uncompressed_len);

	zin.next_in = (Bytef*) (*chunk)->data;
	zin.avail_in = (*chunk)->len - sizeof(uint32);
	zin.next_out = (Bytef*) uncompressed;
	zin.avail_out = uncompressed_len;

	if ( inflate(&zin, Z_SYNC_FLUSH) != Z_OK )
		{
		error = zin.msg;
		return false;
		}

	if ( zin.avail_in > 0 )
		{
		error = "compressed data longer than expected";
		return false;
		}

	(*chunk)->free_func((*chunk)->data);

	uncompressed_bytes_read += uncompressed_len;

	(*chunk)->len = uncompressed_len;
	(*chunk)->data = uncompressed;
	(*chunk)->free_func = Chunk::free_func_delete;

	return true;
	}

bool CompressedChunkedIO::Write(Chunk* chunk)
	{
	if ( (! compress) || IsPure() )
		// No compression.
		return io->Write(chunk);

	// We compress block-wise (rather than stream-wise) because:
	//
	// (1) it's significantly easier to implement due to our block-oriented
	// communication model (with a stream compression, we'd need to chop
	// the stream into blocks during decompression which would require
	// additional buffering and copying).
	//
	// (2) it ensures that we do not introduce any additional latencies (a
	// stream compression may decide to wait for the next chunk of data
	// before writing anything out).
	//
	// The block-wise compression comes at the cost of a smaller compression
	// factor.
	//
	// A compressed chunk's data looks like this:
	//   char[] compressed data
	//   uint32 uncompressed_length
	//
	// By including uncompressed_length, we again trade easier
	// decompression for a smaller reduction factor. If uncompressed_length
	// is zero, the data is *not* compressed.

	uncompressed_bytes_written += chunk->len;
	uint32 original_size = chunk->len;

	char* compressed = new char[chunk->len + sizeof(uint32)];

	if ( chunk->len < MIN_COMPRESS_SIZE )
		{
		// Too small; not worth any compression.
		memcpy(compressed, chunk->data, chunk->len);
		*(uint32*) (compressed + chunk->len) = 0; // uncompressed_length

		chunk->free_func(chunk->data);
		chunk->data = compressed;
		chunk->free_func = Chunk::free_func_delete;
		chunk->len += 4;

		DBG_LOG(DBG_CHUNKEDIO, "zlib write pass-through: size=%d", chunk->len);
		}
	else
		{
		zout.next_in = (Bytef*) chunk->data;
		zout.avail_in = chunk->len;
		zout.next_out = (Bytef*) compressed;
		zout.avail_out = chunk->len;

		if ( deflate(&zout, Z_SYNC_FLUSH) != Z_OK )
			{
			error = zout.msg;
			return false;
			}

		while ( zout.avail_out == 0 )
			{
			// D'oh! Not enough space, i.e., it hasn't got smaller.
			char* old = compressed;
			int old_size = (char*) zout.next_out - compressed;
			int new_size = old_size * 2 + sizeof(uint32);

			compressed = new char[new_size];
			memcpy(compressed, old, old_size);
			delete [] old;

			zout.next_out = (Bytef*) (compressed + old_size);
			zout.avail_out = old_size; // Sic! We doubled.

			if ( deflate(&zout, Z_SYNC_FLUSH) != Z_OK )
				{
				error = zout.msg;
				return false;
				}
			}

		*(uint32*) zout.next_out = original_size; // uncompressed_length

		chunk->free_func(chunk->data);
		chunk->data = compressed;
		chunk->free_func = Chunk::free_func_delete;
		chunk->len =
			((char*) zout.next_out - compressed) + sizeof(uint32);

		DBG_LOG(DBG_CHUNKEDIO, "zlib write: size=%d compressed=%d",
			original_size, chunk->len);
		}

	return io->Write(chunk);
	}

void CompressedChunkedIO::Stats(char* buffer, int length)
	{
	const Statistics* stats = io->Stats();

	int i = snprintf(buffer, length, "compression=%.2f/%.2f ",
			uncompressed_bytes_read ? double(stats->bytes_read) / uncompressed_bytes_read : -1,
			uncompressed_bytes_written ? double(stats->bytes_written) / uncompressed_bytes_written : -1 );

	io->Stats(buffer + i, length - i);
	buffer[length-1] = '\0';
	}
