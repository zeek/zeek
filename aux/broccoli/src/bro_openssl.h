/*
       B R O C C O L I  --  The Bro Client Communications Library

Copyright (C) 2004-2008 Christian Kreibich <christian (at) icir.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies of the Software and its documentation and acknowledgment shall be
given in the documentation and software packages that this Software was
used.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#ifndef broccoli_openssl_h
#define broccoli_openssl_h

#include <broccoli.h>

int       __bro_openssl_init(void);
int       __bro_openssl_encrypted(void);
int       __bro_openssl_rand_bytes(u_char *buf, int num);

int       __bro_openssl_connect(BroConn *bc);

/* Like __bro_openssl_connect, but uses gross manual-connect hack to make
 * sure peer is actually available.
 */
int       __bro_openssl_reconnect(BroConn *bc);

void      __bro_openssl_shutdown(BroConn *bc);

int       __bro_openssl_read(BroConn *bc, uchar *buf, uint buf_size);

/**
 * __bro_openssl_write - writes a chunk of data to the connection.
 * @bc: Bro connection handle.
 * @buf: buffer of data to write.
 * @buf_size: size of buffer pointed to by @buf.
 *
 * Returns: value < 0 on error, 1 if all data was written, 0
 * otherwise (*no* data being written).
 */
int       __bro_openssl_write(BroConn *bc, uchar *buf, uint buf_size);

#endif
