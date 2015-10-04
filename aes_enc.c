/* aes_enc.c */
/*
    This file is part of the ARM-Crypto-Lib.
    Copyright (C) 2006-2010  Daniel Otte (daniel.otte@rub.de)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * \file     aes_enc.c
 * \email    daniel.otte@rub.de
 * \author   Daniel Otte 
 * \date     2008-12-30
 * \license  GPLv3 or later
 * 
 */

#include <stdint.h>
#include <string.h>
#include "aes.h"
#include "gf256mul.h"
#include "aes_sbox.h"
#include "aes_enc.h"

#include "hexdump.h"

#define ROTR32(a, n) \
    (((a) >> (n)) | ((a) << (32 - (n))))

#define GF256MUL_1(a) (a)
#define GF256MUL_2(a) (gf256mul(2, (a), 0x1b))
#define GF256MUL_3(a) (gf256mul(3, (a), 0x1b))

typedef struct {
    uint32_t a[4];
} new_aes_state_t;
/*
static void dump_state(new_aes_state_t *x) {
    int i;
    for (i = 0; i < 4; ++i) {
        printf("    %02x %02x %02x %02x\n", (uint8_t)x->a[i], (uint8_t)(x->a[i] >> 8), (uint8_t)(x->a[i] >> 16), (uint8_t)(x->a[i] >> 24) );
    }
    puts("");
}
*/

#define dump_state(a)
#define printf(...)
#define puts(a)

uint32_t qxtimes(uint32_t a);
/*{
    uint32_t b = a & 0x80808080;
    uint32_t r = (a << 1) & 0xfefefefe;
    r ^= (b >> 7) ^ (b >> 6) ^ (b >> 4) ^ (b >> 3);
    return r;
}*/

void sbox(new_aes_state_t *x);
/*{
    uint8_t i;
    for (i = 0; i < 16; ++i) {
        ((uint8_t*)x->a)[i] = aes_sbox[((uint8_t*)x->a)[i]];
    }
}
*/
void key_xor(new_aes_state_t *x, const uint8_t* key);
/*
 {
    uint8_t i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            ((uint8_t*)x->a)[j * 4 + i] ^= key[i * 4 + j];
        }
    }
}
*/

void convert(void *dest, const void *src);
/*{
    uint8_t i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            (((uint8_t*)dest))[j * 4 + i] = ((const uint8_t*)src)[i * 4 + j];
        }
    }
}
*/

static
void aes_enc_round(new_aes_state_t* state, const aes_roundkey_t* k){
	uint32_t tm, tmp, v;
    /* subBytes */
	printf("pre subbytes\n");
	dump_state(state);
	sbox(state);
	/* shiftRows */
    printf("pre shiftrows\n");
    dump_state(state);
	state->a[1] = ROTR32(state->a[1], 8);
    state->a[2] = ROTR32(state->a[2], 16);
    state->a[3] = ROTR32(state->a[3], 24);
	/* mixColums */
    printf("pre mixcolums\n");
    dump_state(state);
    v = state->a[0];
    tmp = state->a[0] ^ state->a[1] ^ state->a[2] ^ state->a[3];

    tm = qxtimes(state->a[0] ^ state->a[1]);
    state->a[0] ^= tm ^ tmp;

    tm = qxtimes(state->a[1] ^ state->a[2]);
    state->a[1] ^= tm ^ tmp;

    tm = qxtimes(state->a[2] ^ state->a[3]);
    state->a[2] ^= tm ^ tmp;

    tm = qxtimes(state->a[3] ^ v);
    state->a[3] ^= tm ^ tmp;

    /* addKey */
    printf("pre keyadd\n");
    dump_state(state);
	key_xor(state, k->ks);
    printf("fin\n");
    dump_state(state);
}


static
void aes_enc_lastround(new_aes_state_t* state,const aes_roundkey_t* k){
    /* subBytes */
    sbox(state);
    /* shiftRows */
    state->a[1] = ROTR32(state->a[1], 8);
    state->a[2] = ROTR32(state->a[2], 16);
    state->a[3] = ROTR32(state->a[3], 24);
    /* addKey */
    key_xor(state, k->ks);
}

void aes_encrypt_core(void* buffer, const aes_genctx_t* ks, uint8_t rounds){
	uint8_t i;
	new_aes_state_t ctx;
	convert(&ctx.a, buffer);
    printf("pre keyadd\n");
    dump_state(&ctx);
	key_xor(&ctx, ks->key[0].ks);
	i=1;
	for(;rounds>1;--rounds){
	    printf("\n== round %d ==", i);
		aes_enc_round(&ctx, &(ks->key[i]));
		++i;
	}
	aes_enc_lastround(&ctx, &(ks->key[i]));
	convert(buffer, &ctx.a);
}
