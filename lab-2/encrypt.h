/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
 * which can be found via http://creativecommons.org (and should be included as 
 * LICENSE.txt within the associated archive or repository).
 */

#ifndef __ENCRYPT_H
#define __ENCRYPT_H

#include  <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h> 

typedef uint8_t aes_gf28_t;

aes_gf28_t aes_gf28_mulx ( aes_gf28_t a );
aes_gf28_t aes_gf28_mul ( aes_gf28_t a, aes_gf28_t b );
aes_gf28_t aes_gf28_inv ( aes_gf28_t a );
aes_gf28_t aes_enc_sbox ( aes_gf28_t a );
aes_gf28_t aes_dec_sbox ( aes_gf28_t a );

#endif
