/*-
 * Copyright 2014 Alexander Peslyak
 * Copyright 2017 ohac
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "yescrypt.h"
#include "sha256.c"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include "miner.h"

#define YESCRYPT_FLAGS (YESCRYPT_RW | YESCRYPT_PWXFORM)

static int yescrypt_bsty(const uint8_t * passwd, size_t passwdlen,
    const uint8_t * salt, size_t saltlen, uint64_t N, uint32_t r, uint32_t p,
    uint8_t * buf, size_t buflen)
{
	static __thread int initialized = 0;
	static __thread yescrypt_shared_t shared;
	static __thread yescrypt_local_t local;
	int retval;

	if (!initialized) {
		if (yescrypt_init_shared(&shared, NULL, 0,
		    0, 0, 0, YESCRYPT_SHARED_DEFAULTS, 0, NULL, 0))
			return -1;
		if (yescrypt_init_local(&local)) {
			yescrypt_free_shared(&shared);
			return -1;
		}
		initialized = 1;
	}
	retval = yescrypt_kdf(&shared, &local,
	    passwd, passwdlen, salt, saltlen, N, r, p, 0, YESCRYPT_FLAGS,
	    buf, buflen);
	return retval;
}

void yescrypt_hash(const char *input, char *output, uint32_t len)
{
	yescrypt_bsty((uint8_t*)input, len, (uint8_t*)input, len, 2048, 8, 1, (uint8_t*)output, 32);
}

const char* sha256d_str(
		const char *coinb1str,
		const char *xnonce1str,
		const char *xnonce2str,
		const char *coinb2str,
		const char *merklestr)
{
	unsigned char merkle_root[64];
	unsigned char buff[256];
	static char rv[64 + 1];
	size_t coinb1_size = strlen(coinb1str) / 2;
	size_t xnonce1_size = strlen(xnonce1str) / 2;
	size_t xnonce2_size = strlen(xnonce2str) / 2;
	size_t coinb2_size = strlen(coinb2str) / 2;
	size_t coinbase_size = coinb1_size + xnonce1_size + xnonce2_size + coinb2_size;
	int merkle_count = strlen(merklestr) / (32 * 2);
	int i;
	unsigned char coinbase[256];

	hex2bin(coinbase, coinb1str, coinb1_size);
	hex2bin(coinbase + coinb1_size, xnonce1str, xnonce1_size);
	hex2bin(coinbase + coinb1_size + xnonce1_size, xnonce2str, xnonce2_size);
	hex2bin(coinbase + coinb1_size + xnonce1_size + xnonce2_size, coinb2str, coinb2_size);
	sha256d(merkle_root, coinbase, coinbase_size);

	for (i = 0; i < merkle_count; i++) {
		hex2bin(merkle_root + 32, merklestr + i * 32 * 2, 32);
		sha256d(merkle_root, merkle_root, 64);
	}
	bin2hex(rv, merkle_root, 32);
	return rv;
}
