// $Id: bdcat.cc 6 2004-04-30 00:31:26Z jason $
//
// Decrypts Bro's log files.
//
// Usage: bdcat [-k file-with-secret-rsa-key] [files...]
//
// The key file may be alternatively set via the env variable BDCAT_KEY.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/err.h"

EVP_PKEY* SecKey = 0;
EVP_CIPHER* CipherType = 0;

void cryptcat(FILE* f)
	{
	unsigned char magic[7];
	unsigned long secret_len;

	// Read file header.
	if ( ! (fread(&magic, 7, 1, f) &&
		fread(&secret_len, sizeof(secret_len), 1, f)) )
		{
		fprintf(stderr, "can't read file header: %s\n", strerror(errno));
		exit(1);
		}

	if ( memcmp("BROENC1", (const char*) magic, 7) != 0 )
		{
		fputs("not a Bro encrypted file\n", stderr);
		exit(1);
		}

	secret_len = ntohl(secret_len);
	int iv_len = EVP_CIPHER_iv_length(CipherType);
	unsigned char secret[secret_len];
	unsigned char iv[iv_len];

	if ( ! (fread(&secret, secret_len, 1, f) &&
		fread(&iv, iv_len, 1, f)) )
		{
		fprintf(stderr, "can't read file header: %s\n", strerror(errno));
		exit(1);
		}

	// Decrypt data.
	EVP_CIPHER_CTX cipher_ctx;
	if ( ! EVP_OpenInit(&cipher_ctx, CipherType,
				secret, secret_len, iv, SecKey) )
		{
		fprintf( stderr, "can't init decryption: %s\n",
				ERR_error_string(ERR_get_error(), 0));
		exit(1);
		return;
		}

	int block_size = EVP_CIPHER_block_size(CipherType);
	unsigned char buffer_in[block_size];
	unsigned char buffer_out[block_size];

	int inl, outl;
	while ( (inl = fread(buffer_in, 1, block_size, f)) )
		{
		if ( ! EVP_OpenUpdate(&cipher_ctx, buffer_out,
					&outl, buffer_in, inl) )
			{
			fprintf( stderr, "can't decrypt: %s\n",
				 ERR_error_string(ERR_get_error(), 0));
			exit(1);
			}

		if ( outl && ! fwrite(buffer_out, outl, 1, stdout) )
			{
			fprintf(stderr, "can't write to stdout: %s\n",
					strerror(errno));
			exit(1);
			}
		}

	if ( ! EVP_OpenFinal(&cipher_ctx, buffer_out, &outl) )
		{
		fprintf( stderr, "can't decrypt: %s\n",
				 ERR_error_string(ERR_get_error(), 0));
		exit(1);
		}

	if ( outl && ! fwrite(buffer_out, outl, 1, stdout) )
		{
		fprintf(stderr, "can't write to stdout: %s\n", strerror(errno));
		exit(1);
		}

	fclose(f);
	}

void Usage()
	{
	fprintf(stderr, "bdcat [-k <sec-key-file>] [files]\n");
	exit(1);
	}

int main(int argc, char** argv)
	{
	char* keyfile = getenv("BDCAT_KEY");

	// Read options.
	char op;
	while ( (op = getopt(argc, argv, "k:")) >= 0 )
		{
		if ( op == 'k' )
			keyfile = optarg;
		else
			Usage();
		}

	if ( ! keyfile )
		{
		fputs("no keyfile given\n", stderr);
		exit(1);
		}

	// Init crypto.

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	FILE* f = fopen(keyfile, "r");
	if ( ! f )
		{
		fprintf(stderr, "can't open key file %s: %s\n",
				keyfile, strerror(errno));
		exit(1);
		}

	SecKey = PEM_read_PrivateKey(f, 0, 0, 0);
	if ( ! SecKey )
		{
		fprintf(stderr, "can't read key from %s: %s\n", keyfile,
				ERR_error_string(ERR_get_error(), 0));
		exit(1);
		}

	fclose(f);

	// Depending on the OpenSSL version, EVP_*_cbc()
	// returns a const or a non-const.
	CipherType = (EVP_CIPHER*) EVP_bf_cbc();

	// Decrypt the files.
	if ( optind == argc )
		cryptcat(stdin);
	else
		{
		while ( optind < argc )
			{
			FILE* f = fopen(argv[optind], "r");
			if ( ! f )
				{
				fprintf(stderr, "can't open %s: %s\n",
						argv[optind], strerror(errno));
				exit(1);
				}

			cryptcat(f);
			++optind;
			}
		}
	}
