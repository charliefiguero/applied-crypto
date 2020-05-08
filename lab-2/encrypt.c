/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include "encrypt.h"

const int Nr = 4;
const int Nb = 4;

aes_gf28_col_t AES_ENC_TBOX_0 [256] = { 0 };
aes_gf28_col_t AES_ENC_TBOX_1 [256] = { 0 };
aes_gf28_col_t AES_ENC_TBOX_2 [256] = { 0 };
aes_gf28_col_t AES_ENC_TBOX_3 [256] = { 0 };
aes_gf28_col_t AES_ENC_TBOX_4 [256] = { 0 };
 
static const aes_gf28_t sbox_lookup[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

// void compute_sboxes() {
//     for ( int i = 0; i < 256; i++ ) {
//         sbox_lookup[(uint8_t)i] = aes_enc_sbox ( (uint8_t)i );
//     }
// }

int main( int argc, char* argv[] ) {
    const aes_gf28_t k[ 16 ] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
    const uint8_t m[ 16 ] = { 0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 };
    aes_gf28_t c[ 16 ] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };
    aes_gf28_t t[ 16 ];

    // compute_TBoxes();
    // compute_sboxes();

    // AES_KEY rk;
    // AES_set_encrypt_key( k, 128, &rk );
    // AES_encrypt( m, t, &rk );

    aes_enc( t, m, k ); // <- here is the bug?

    for (int i = 0; i < 16; i++) {
      printf("%d, %d\n", t[i], c[i]);
    }

    if( !memcmp( t, c, 16 * sizeof( aes_gf28_t ) ) ) { printf( "AES.Enc( k, m ) == c\n" ); }
    else { printf( "AES.Enc( k, m ) != c\n" ); }
}

aes_gf28_t aes_gf28_mulx ( aes_gf28_t a ) {
    if( ( a & 0x80 ) == 0x80 ) { return 0x1B ^ ( a << 1 ); }
    else                       { return ( a << 1 );        }
}

// using mulx to reduce intermediate results during polynomial multiplication
aes_gf28_t aes_gf28_mul ( aes_gf28_t a, aes_gf28_t b ) {
    aes_gf28_t t = 0;

    for( int i = 7; i >= 0; i-- ) {
        t = aes_gf28_mulx ( t );

        if( ( b >> i ) & 1 ) {
            t ^= a;
        }
    }

    return t;
}

// using Langrange's theorem
aes_gf28_t aes_gf28_inv ( aes_gf28_t a ) {
    aes_gf28_t t_0 = aes_gf28_mul ( a, a ); // a^2
    aes_gf28_t t_1 = aes_gf28_mul ( t_0 , a ); // a^3
    t_0 = aes_gf28_mul ( t_0 , t_0 ); // a^4
    t_1 = aes_gf28_mul ( t_1 , t_0 ); // a^7
    t_0 = aes_gf28_mul ( t_0 , t_0 ); // a^8
    t_0 = aes_gf28_mul ( t_1 , t_0 ); // a^15
    t_0 = aes_gf28_mul ( t_0 , t_0 ); // a^30
    t_0 = aes_gf28_mul ( t_0 , t_0 ); // a^60
    t_1 = aes_gf28_mul ( t_1 , t_0 ); // a^67
    t_0 = aes_gf28_mul ( t_0 , t_1 ); // a^127
    t_0 = aes_gf28_mul ( t_0 , t_0 ); // a^254

    return t_0;
}

aes_gf28_t aes_enc_sbox ( aes_gf28_t a ) {
    a = aes_gf28_inv ( a );

    a = ( 0x63 ) ^ // 0 1 1 0 0 0 1 1
    ( a ) ^ // a_7 a_6 a_5 a_4 a_3 a_2 a_1 a_0
    ( a << 1 ) ^ // a_6 a_5 a_4 a_3 a_2 a_1 a_0 0
    ( a << 2 ) ^ // a_5 a_4 a_3 a_2 a_1 a_0 0 0
    ( a << 3 ) ^ // a_4 a_3 a_2 a_1 a_0 0 0 0
    ( a << 4 ) ^ // a_3 a_2 a_1 a_0 0 0 0 0
    ( a >> 7 ) ^ // 0 0 0 0 0 0 0 a_7
    ( a >> 6 ) ^ // 0 0 0 0 0 0 a_7 a_6
    ( a >> 5 ) ^ // 0 0 0 0 0 a_7 a_6 a_5
    ( a >> 4 ) ; // 0 0 0 0 a_7 a_6 a_5 a_4

    return a;
}

// Never use this as we are only encrypting 

// aes_gf28_t aes_dec_sbox ( aes_gf28_t a ) {
//     a = ( 0x05 ) ^ // 0 0 0 0 0 1 0 1
//     ( a << 1 ) ^ // a_6 a_5 a_4 a_3 a_2 a_1 a_0 0
//     ( a << 3 ) ^ // a_4 a_3 a_2 a_1 a_0 0 0 0
//     ( a << 6 ) ^ // a_1 a_0 0 0 0 0 0 0
//     ( a >> 7 ) ^ // 0 0 0 0 0 0 0 a_7
//     ( a >> 5 ) ^ // 0 0 0 0 0 a_7 a_6 a_5
//     ( a >> 2 ) ; // 0 0 a_7 a_6 a_5 a_4 a_3 a_2

//     a = aes_gf28_inv ( a );
//     return a;
// }

void aes_enc_keyexp_step ( uint8_t* r, const uint8_t* rk , uint8_t rc ) {
    r[ 0 ] = rc ^ aes_enc_sbox ( rk[ 13 ] ) ^ rk[ 0 ];
    r[ 1 ] = aes_enc_sbox ( rk[ 14 ] ) ^ rk[ 1 ];
    r[ 2 ] = aes_enc_sbox ( rk[ 15 ] ) ^ rk[ 2 ];
    r[ 3 ] = aes_enc_sbox ( rk[ 12 ] ) ^ rk[ 3 ];

    r[ 4 ] = r[ 0 ] ^ rk[ 4 ];
    r[ 5 ] = r[ 1 ] ^ rk[ 5 ];
    r[ 6 ] = r[ 2 ] ^ rk[ 6 ];
    r[ 7 ] = r[ 3 ] ^ rk[ 7 ];

    r[ 8 ] = r[ 4 ] ^ rk[ 8 ];
    r[ 9 ] = r[ 5 ] ^ rk[ 9 ];
    r[ 10 ] = r[ 6 ] ^ rk[ 10 ];
    r[ 11 ] = r[ 7 ] ^ rk[ 11 ];

    r[ 12 ] = r[ 8 ] ^ rk[ 12 ];
    r[ 13 ] = r[ 9 ] ^ rk[ 13 ];
    r[ 14 ] = r[ 10 ] ^ rk[ 14 ];
    r[ 15 ] = r[ 11 ] ^ rk[ 15 ];
}

#define AES_ENC_RND_KEY_STEP(a,b,c,d) { \
    s[ a ] = s[ a ] ^ rk[ a ]; \
    s[ b ] = s[ b ] ^ rk[ b ]; \
    s[ c ] = s[ c ] ^ rk[ c ]; \
    s[ d ] = s[ d ] ^ rk[ d ]; \
}

void aes_enc_rnd_key ( aes_gf28_t * s, const aes_gf28_t * rk ) {
    AES_ENC_RND_KEY_STEP ( 0, 1, 2, 3 );
    AES_ENC_RND_KEY_STEP ( 4, 5, 6, 7 );
    AES_ENC_RND_KEY_STEP ( 8, 9, 10, 11 );
    AES_ENC_RND_KEY_STEP ( 12, 13, 14, 15 );
}

#define AES_ENC_RND_SUB_STEP(a,b,c,d) { \
    s[ a ] = sbox_lookup [ s[ a ] ]; \
    s[ b ] = sbox_lookup [ s[ b ] ]; \
    s[ c ] = sbox_lookup [ s[ c ] ]; \
    s[ d ] = sbox_lookup [ s[ d ] ]; \
}

void aes_enc_rnd_sub ( aes_gf28_t * s ) {
    AES_ENC_RND_SUB_STEP ( 0, 1, 2, 3 );
    AES_ENC_RND_SUB_STEP ( 4, 5, 6, 7 );
    AES_ENC_RND_SUB_STEP ( 8, 9, 10, 11 );
    AES_ENC_RND_SUB_STEP ( 12, 13, 14, 15 );
}

#define AES_ENC_RND_ROW_STEP(a,b,c,d,e,f,g,h) { \
    aes_gf28_t __a1 = s[ a ]; \
    aes_gf28_t __b1 = s[ b ]; \
    aes_gf28_t __c1 = s[ c ]; \
    aes_gf28_t __d1 = s[ d ]; \
                              \
    s[ e ] = __a1; \
    s[ f ] = __b1; \
    s[ g ] = __c1; \
    s[ h ] = __d1; \
}

void aes_enc_rnd_row ( aes_gf28_t * s ) {
    AES_ENC_RND_ROW_STEP ( 1, 5, 9, 13, 13, 1, 5, 9 );
    AES_ENC_RND_ROW_STEP ( 2, 6, 10, 14, 10, 14, 2, 6 );
    AES_ENC_RND_ROW_STEP ( 3, 7, 11, 15, 7, 11, 15, 3 );
}

#define AES_ENC_RND_MIX_STEP(a,b,c,d) { \
    aes_gf28_t __a1 = s[ a ]; \
    aes_gf28_t __b1 = s[ b ]; \
    aes_gf28_t __c1 = s[ c ]; \
    aes_gf28_t __d1 = s[ d ]; \
                              \
    aes_gf28_t __a2 = aes_gf28_mulx ( __a1 ); \
    aes_gf28_t __b2 = aes_gf28_mulx ( __b1 ); \
    aes_gf28_t __c2 = aes_gf28_mulx ( __c1 ); \
    aes_gf28_t __d2 = aes_gf28_mulx ( __d1 ); \
                                              \
    aes_gf28_t __a3 = __a1 ^ __a2; \
    aes_gf28_t __b3 = __b1 ^ __b2; \
    aes_gf28_t __c3 = __c1 ^ __c2; \
    aes_gf28_t __d3 = __d1 ^ __d2; \
                                   \
    s[ a ] = __a2 ^ __b3 ^ __c1 ^ __d1; \
    s[ b ] = __a1 ^ __b2 ^ __c3 ^ __d1; \
    s[ c ] = __a1 ^ __b1 ^ __c2 ^ __d3; \
    s[ d ] = __a3 ^ __b1 ^ __c1 ^ __d2; \
}

void aes_enc_rnd_mix ( aes_gf28_t * s ) {
    AES_ENC_RND_MIX_STEP ( 0, 1, 2, 3 );
    AES_ENC_RND_MIX_STEP ( 4, 5, 6, 7 );
    AES_ENC_RND_MIX_STEP ( 8, 9, 10, 11 );
    AES_ENC_RND_MIX_STEP ( 12, 13, 14, 15 );
}

// high runtime, low footprint 
void aes_enc( uint8_t* r, const uint8_t* m, const uint8_t* k ) {
    // number of columns (blocks?)
    int Nb = 4;
    // number of rounds
    int Nr = 10;

    // AES round constants: 2^Rn
    uint8_t AES_RC[] = {0x11, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

    //round key and state matrix containing message
    aes_gf28_t rk[ 4 * Nb ], s[ 4 * Nb ];

    // round constant pointer
    aes_gf28_t * rcp = AES_RC;
    // round key pointer
    aes_gf28_t * rkp = rk;

    // copy the message into the state matrix
    memcpy ( s, m, 16 );
    // copy the key into the round key matrix pointed at by rkp
    memcpy ( rkp, k, 16 );

    // 1 initial round
    aes_enc_rnd_key ( s, rkp );
    // Nr - 1 iterated rounds
    for( int i = 1; i < Nr; i++ ) {
    aes_enc_rnd_sub ( s );
    aes_enc_rnd_row ( s );
    aes_enc_rnd_mix ( s );
    aes_enc_keyexp_step ( rkp , rkp , *(++ rcp) );
    aes_enc_rnd_key ( s, rkp );
    }
    // 1 final round
    aes_enc_rnd_sub ( s );
    aes_enc_rnd_row ( s );
    aes_enc_keyexp_step ( rkp , rkp , *(++ rcp) );
    aes_enc_rnd_key ( s, rkp );

    memcpy( r, s, 16 );
}

void U8_TO_U32_LE ( aes_gf28_col_t* t, const uint8_t* m, int x ) {
    *t =  m[x] << 0| m[x+1] << 8| m[x+2] << 16| m[x+3] << 24;
}

void U32_TO_U8_LE ( uint8_t* r, const aes_gf28_col_t t, int x) {
    r[x + 0] = (t >> 0) & 0xFF;
    r[x + 1] = (t >> 8) & 0xFF;
    r[x + 2] = (t >> 16) & 0xFF;
    r[x + 3] = (t >> 24) & 0xFF;
}

#define AES_ENC_RND_INIT() { \
    t_0 = rkp[ 0 ] ^ t_0; \
    t_1 = rkp[ 1 ] ^ t_1; \
    t_2 = rkp[ 2 ] ^ t_2; \
    t_3 = rkp[ 3 ] ^ t_3; \
    \
    rkp += Nb; \
}

#define AES_ENC_RND_ITER() { \
    t_4 = rkp[ 0 ] ^ ( AES_ENC_TBOX_0 [ ( t_0 >> 0 ) & 0xFF ] ) ^ \
    ( AES_ENC_TBOX_1 [ ( t_1 >> 8 ) & 0xFF ] ) ^ \
    ( AES_ENC_TBOX_2 [ ( t_2 >> 16 ) & 0xFF ] ) ^ \
    ( AES_ENC_TBOX_3 [ ( t_3 >> 24 ) & 0xFF ] ) ; \
    t_5 = rkp[ 1 ] ^ ( AES_ENC_TBOX_0 [ ( t_1 >> 0 ) & 0xFF ] ) ^ \
    ( AES_ENC_TBOX_1 [ ( t_2 >> 8 ) & 0xFF ] ) ^ \
    ( AES_ENC_TBOX_2 [ ( t_3 >> 16 ) & 0xFF ] ) ^ \
    ( AES_ENC_TBOX_3 [ ( t_0 >> 24 ) & 0xFF ] ) ; \
    t_6 = rkp[ 2 ] ^ ( AES_ENC_TBOX_0 [ ( t_2 >> 0 ) & 0xFF ] ) ^ \
    ( AES_ENC_TBOX_1 [ ( t_3 >> 8 ) & 0xFF ] ) ^ \
    ( AES_ENC_TBOX_2 [ ( t_0 >> 16 ) & 0xFF ] ) ^ \
    ( AES_ENC_TBOX_3 [ ( t_1 >> 24 ) & 0xFF ] ) ; \
    t_7 = rkp[ 3 ] ^ ( AES_ENC_TBOX_0 [ ( t_3 >> 0 ) & 0xFF ] ) ^ \
    ( AES_ENC_TBOX_1 [ ( t_0 >> 8 ) & 0xFF ] ) ^ \
    ( AES_ENC_TBOX_2 [ ( t_1 >> 16 ) & 0xFF ] ) ^ \
    ( AES_ENC_TBOX_3 [ ( t_2 >> 24 ) & 0xFF ] ) ; \
    \
    rkp += Nb; t_0 = t_4; t_1 = t_5; t_2 = t_6; t_3 = t_7; \
}

#define AES_ENC_RND_FINI() { \
    t_4 = rkp[ 0 ] ^ ( AES_ENC_TBOX_4 [ ( t_0 >> 0 ) & 0xFF ] & 0x000000FF ) ^ \
    ( AES_ENC_TBOX_4 [ ( t_1 >> 8 ) & 0xFF ] & 0x0000FF00 ) ^ \
    ( AES_ENC_TBOX_4 [ ( t_2 >> 16 ) & 0xFF ] & 0x00FF0000 ) ^ \
    ( AES_ENC_TBOX_4 [ ( t_3 >> 24 ) & 0xFF ] & 0xFF000000 ) ; \
    t_5 = rkp[ 1 ] ^ ( AES_ENC_TBOX_4 [ ( t_1 >> 0 ) & 0xFF ] & 0x000000FF ) ^ \
    ( AES_ENC_TBOX_4 [ ( t_2 >> 8 ) & 0xFF ] & 0x0000FF00 ) ^ \
    ( AES_ENC_TBOX_4 [ ( t_3 >> 16 ) & 0xFF ] & 0x00FF0000 ) ^ \
    ( AES_ENC_TBOX_4 [ ( t_0 >> 24 ) & 0xFF ] & 0xFF000000 ) ; \
    t_6 = rkp[ 2 ] ^ ( AES_ENC_TBOX_4 [ ( t_2 >> 0 ) & 0xFF ] & 0x000000FF ) ^ \
    ( AES_ENC_TBOX_4 [ ( t_3 >> 8 ) & 0xFF ] & 0x0000FF00 ) ^ \
    ( AES_ENC_TBOX_4 [ ( t_0 >> 16 ) & 0xFF ] & 0x00FF0000 ) ^ \
    ( AES_ENC_TBOX_4 [ ( t_1 >> 24 ) & 0xFF ] & 0xFF000000 ) ; \
    t_7 = rkp[ 3 ] ^ ( AES_ENC_TBOX_4 [ ( t_3 >> 0 ) & 0xFF ] & 0x000000FF ) ^ \
    ( AES_ENC_TBOX_4 [ ( t_0 >> 8 ) & 0xFF ] & 0x0000FF00 ) ^ \
    ( AES_ENC_TBOX_4 [ ( t_1 >> 16 ) & 0xFF ] & 0x00FF0000 ) ^ \
    ( AES_ENC_TBOX_4 [ ( t_2 >> 24 ) & 0xFF ] & 0xFF000000 ) ; \
    \
    rkp += Nb; t_0 = t_4; t_1 = t_5; t_2 = t_6; t_3 = t_7; \
}

void compute_TBoxes() {
  for (int i = 0; i < 256; i++) {
    AES_ENC_TBOX_0[i] = aes_gf28_mul(2, aes_enc_sbox(i)) << 0 |
                        aes_gf28_mul(1, aes_enc_sbox(i)) << 8 |
                        aes_gf28_mul(1, aes_enc_sbox(i)) << 16 |
                        aes_gf28_mul(3, aes_enc_sbox(i)) << 24;
    AES_ENC_TBOX_1[i] = aes_gf28_mul(3, aes_enc_sbox(i)) << 0 |
                        aes_gf28_mul(2, aes_enc_sbox(i)) << 8 |
                        aes_gf28_mul(1, aes_enc_sbox(i)) << 16 |
                        aes_gf28_mul(1, aes_enc_sbox(i)) << 24;
    AES_ENC_TBOX_2[i] = aes_gf28_mul(1, aes_enc_sbox(i)) << 0 |
                        aes_gf28_mul(3, aes_enc_sbox(i)) << 8 |
                        aes_gf28_mul(2, aes_enc_sbox(i)) << 16 |
                        aes_gf28_mul(1, aes_enc_sbox(i)) << 24;
    AES_ENC_TBOX_3[i] = aes_gf28_mul(1, aes_enc_sbox(i)) << 0 |
                        aes_gf28_mul(1, aes_enc_sbox(i)) << 8 |
                        aes_gf28_mul(3, aes_enc_sbox(i)) << 16 |
                        aes_gf28_mul(2, aes_enc_sbox(i)) << 24;
    AES_ENC_TBOX_4[i] = aes_enc_sbox(i) << 0  |
                        aes_enc_sbox(i) << 8  |
                        aes_enc_sbox(i) << 16 |
                        aes_enc_sbox(i) << 24;
  }
}

// high footprint, low latency version 
// void aes_enc( uint8_t* r, const uint8_t* m, const aes_gf28_t* k ) {
//   aes_gf28_col_t *rkp = ( aes_gf28_col_t * ) k ;
//   aes_gf28_col_t t_0 , t_1 , t_2 , t_3, t_4 , t_5 , t_6 , t_7;
// 
//   U8_TO_U32_LE ( &t_0, m, 0  ); U8_TO_U32_LE ( &t_1, m, 8  );
//   U8_TO_U32_LE ( &t_2, m, 4  ); U8_TO_U32_LE ( &t_3, m, 12 );

//   // 1 initial round
//   AES_ENC_RND_INIT();

//   // Nr - 1 iterated rounds
//   for( int i = 1; i < Nr; i++ ) {
//     AES_ENC_RND_ITER();
//   }

//   // 1 final round
//   AES_ENC_RND_FINI();

//   U32_TO_U8_LE ( r, t_0 , 0 ); U32_TO_U8_LE ( r, t_1 , 4 );
//   U32_TO_U8_LE ( r, t_2 , 8 ); U32_TO_U8_LE ( r, t_3 , 12 );
// }