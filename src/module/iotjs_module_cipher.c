/* Originally from tiny-AES128-C (http://github.com/kokke/tiny-AES128-C)
 * Copyright 2016 Gyeonghwan Hong <redcarrottt@gmail.com> All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "iotjs_def.h"
#include "iotjs_module_buffer.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Interface between jhandler functions and tiny-AES128-C.
void encrypt_aes128_ecb(uint8_t* input, const uint8_t* key, uint8_t* output);
void decrypt_aes128_ecb(uint8_t* input, const uint8_t* key, uint8_t* output);

// The number of columns comprising a state in AES. This is a constant in AES.
#define N_B 4
// The number of 32 bit words in a key.
#define N_K 4
// Key length in bytes [128 bit]
#define KEYLEN 16
// The number of rounds in AES Cipher.
#define N_R 10

// g_state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];
static state_t* g_state;

// The array that stores the round keys.
static uint8_t g_round_key[176];

// The Key input to the AES Program
static const uint8_t* g_key;

// Initial Vector used only for CBC mode
static uint8_t* g_iv;

// The lookup-tables are marked const so they can be placed in read-only storage
// instead of RAM. The numbers below can be computed dynamically trading ROM
// for RAM - This can be useful in (embedded) bootloader applications,
// where ROM is often limited.
static const uint8_t k_sbox[256] =
    { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
      0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
      0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
      0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
      0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
      0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
      0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
      0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
      0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
      0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
      0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
      0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
      0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
      0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
      0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
      0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
      0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
      0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
      0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
      0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
      0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
      0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t k_rsbox[256] =
    { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
      0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
      0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
      0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
      0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
      0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
      0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
      0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
      0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
      0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
      0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
      0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
      0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
      0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
      0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
      0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
      0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
      0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
      0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
      0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
      0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
      0x55, 0x21, 0x0c, 0x7d };


// The round constant word array, k_rcon[i], contains the values given by x to
// the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
// Note that i starts at 1, not 0).
static const uint8_t k_rcon[255] =
    { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
      0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
      0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
      0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
      0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
      0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
      0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
      0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
      0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
      0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e,
      0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
      0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
      0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
      0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
      0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
      0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
      0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb,
      0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
      0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
      0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
      0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
      0x74, 0xe8, 0xcb };

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
static uint8_t get_sbox_value(uint8_t num) {
  return k_sbox[num];
}

static uint8_t get_sbox_invert(uint8_t num) {
  return k_rsbox[num];
}

// This function produces N_B(N_R+1) round keys.
// The round keys are used in each round to decrypt the states.
static void key_expansion(void) {
  uint32_t i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations

  // The first round key is the key itself.
  for (i = 0; i < N_K; ++i) {
    g_round_key[(i * 4) + 0] = g_key[(i * 4) + 0];
    g_round_key[(i * 4) + 1] = g_key[(i * 4) + 1];
    g_round_key[(i * 4) + 2] = g_key[(i * 4) + 2];
    g_round_key[(i * 4) + 3] = g_key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (; (i < (N_B * (N_R + 1))); ++i) {
    for (j = 0; j < 4; ++j) {
      tempa[j] = g_round_key[(i - 1) * 4 + j];
    }
    if (i % N_K == 0) {
      // This function rotates the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        k = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = k;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = get_sbox_value(tempa[0]);
        tempa[1] = get_sbox_value(tempa[1]);
        tempa[2] = get_sbox_value(tempa[2]);
        tempa[3] = get_sbox_value(tempa[3]);
      }

      tempa[0] = tempa[0] ^ k_rcon[i / N_K];
    } else if (N_K > 6 && i % N_K == 4) {
      // Function Subword()
      {
        tempa[0] = get_sbox_value(tempa[0]);
        tempa[1] = get_sbox_value(tempa[1]);
        tempa[2] = get_sbox_value(tempa[2]);
        tempa[3] = get_sbox_value(tempa[3]);
      }
    }
    g_round_key[i * 4 + 0] = g_round_key[(i - N_K) * 4 + 0] ^ tempa[0];
    g_round_key[i * 4 + 1] = g_round_key[(i - N_K) * 4 + 1] ^ tempa[1];
    g_round_key[i * 4 + 2] = g_round_key[(i - N_K) * 4 + 2] ^ tempa[2];
    g_round_key[i * 4 + 3] = g_round_key[(i - N_K) * 4 + 3] ^ tempa[3];
  }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void add_round_key(uint8_t round) {
  uint8_t i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      (*g_state)[i][j] ^= g_round_key[round * N_B * 4 + i * N_B + j];
    }
  }
}

// The sub_bytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void sub_bytes(void) {
  uint8_t i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      (*g_state)[j][i] = get_sbox_value((*g_state)[j][i]);
    }
  }
}

// The shift_rows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void shift_rows(void) {
  uint8_t temp;

  // Rotate first row 1 columns to left
  temp = (*g_state)[0][1];
  (*g_state)[0][1] = (*g_state)[1][1];
  (*g_state)[1][1] = (*g_state)[2][1];
  (*g_state)[2][1] = (*g_state)[3][1];
  (*g_state)[3][1] = temp;

  // Rotate second row 2 columns to left
  temp = (*g_state)[0][2];
  (*g_state)[0][2] = (*g_state)[2][2];
  (*g_state)[2][2] = temp;

  temp = (*g_state)[1][2];
  (*g_state)[1][2] = (*g_state)[3][2];
  (*g_state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp = (*g_state)[0][3];
  (*g_state)[0][3] = (*g_state)[3][3];
  (*g_state)[3][3] = (*g_state)[2][3];
  (*g_state)[2][3] = (*g_state)[1][3];
  (*g_state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x) {
  return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

// mix_columns function mixes the columns of the state matrix
static void mix_columns(void) {
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i) {
    t = (*g_state)[i][0];
    Tmp = (*g_state)[i][0] ^ (*g_state)[i][1] ^ (*g_state)[i][2] ^
          (*g_state)[i][3];

    Tm = (*g_state)[i][0] ^ (*g_state)[i][1];
    Tm = xtime(Tm);
    (*g_state)[i][0] ^= Tm ^ Tmp;

    Tm = (*g_state)[i][1] ^ (*g_state)[i][2];
    Tm = xtime(Tm);
    (*g_state)[i][1] ^= Tm ^ Tmp;

    Tm = (*g_state)[i][2] ^ (*g_state)[i][3];
    Tm = xtime(Tm);
    (*g_state)[i][2] ^= Tm ^ Tmp;

    Tm = (*g_state)[i][3] ^ t;
    Tm = xtime(Tm);
    (*g_state)[i][3] ^= Tm ^ Tmp;
  }
}

#define do_multiply(x, y)                      \
  (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^ \
   ((y >> 2 & 1) * xtime(xtime(x))) ^          \
   ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^   \
   ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))))

// mix_columns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand
// for the inexperienced.
// Please use the references to gain more information.
static void inv_mix_columns(void) {
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i) {
    a = (*g_state)[i][0];
    b = (*g_state)[i][1];
    c = (*g_state)[i][2];
    d = (*g_state)[i][3];

    (*g_state)[i][0] = do_multiply(a, 0x0e) ^ do_multiply(b, 0x0b) ^
                       do_multiply(c, 0x0d) ^ do_multiply(d, 0x09);
    (*g_state)[i][1] = do_multiply(a, 0x09) ^ do_multiply(b, 0x0e) ^
                       do_multiply(c, 0x0b) ^ do_multiply(d, 0x0d);
    (*g_state)[i][2] = do_multiply(a, 0x0d) ^ do_multiply(b, 0x09) ^
                       do_multiply(c, 0x0e) ^ do_multiply(d, 0x0b);
    (*g_state)[i][3] = do_multiply(a, 0x0b) ^ do_multiply(b, 0x0d) ^
                       do_multiply(c, 0x09) ^ do_multiply(d, 0x0e);
  }
}


// The sub_bytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void inv_sub_bytes(void) {
  uint8_t i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      (*g_state)[j][i] = get_sbox_invert((*g_state)[j][i]);
    }
  }
}

static void inv_shift_rows(void) {
  uint8_t temp;

  // Rotate first row 1 columns to right
  temp = (*g_state)[3][1];
  (*g_state)[3][1] = (*g_state)[2][1];
  (*g_state)[2][1] = (*g_state)[1][1];
  (*g_state)[1][1] = (*g_state)[0][1];
  (*g_state)[0][1] = temp;

  // Rotate second row 2 columns to right
  temp = (*g_state)[0][2];
  (*g_state)[0][2] = (*g_state)[2][2];
  (*g_state)[2][2] = temp;

  temp = (*g_state)[1][2];
  (*g_state)[1][2] = (*g_state)[3][2];
  (*g_state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*g_state)[0][3];
  (*g_state)[0][3] = (*g_state)[1][3];
  (*g_state)[1][3] = (*g_state)[2][3];
  (*g_state)[2][3] = (*g_state)[3][3];
  (*g_state)[3][3] = temp;
}


// do_cipher is the main function that encrypts the PlainText.
static void do_cipher(void) {
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  add_round_key(0);

  // There will be N_R rounds.
  // The first N_R-1 rounds are identical.
  // These N_R-1 rounds are executed in the loop below.
  for (round = 1; round < N_R; ++round) {
    sub_bytes();
    shift_rows();
    mix_columns();
    add_round_key(round);
  }

  // The last round is given below.
  // The mix_columns function is not here in the last round.
  sub_bytes();
  shift_rows();
  add_round_key(N_R);
}

static void do_inv_cipher(void) {
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  add_round_key(N_R);

  // There will be N_R rounds.
  // The first N_R-1 rounds are identical.
  // These N_R-1 rounds are executed in the loop below.
  for (round = N_R - 1; round > 0; round--) {
    inv_shift_rows();
    inv_sub_bytes();
    add_round_key(round);
    inv_mix_columns();
  }

  // The last round is given below.
  // The mix_columns function is not here in the last round.
  inv_shift_rows();
  inv_sub_bytes();
  add_round_key(0);
}

static void block_copy(uint8_t* output, uint8_t* input) {
  uint8_t i;
  for (i = 0; i < KEYLEN; ++i) {
    output[i] = input[i];
  }
}

// AES-128 ECB encrypt & decrypt functions
void encrypt_aes128_ecb(uint8_t* input, const uint8_t* key, uint8_t* output) {
  // Copy input to output, and work in-memory on output
  block_copy(output, input);
  g_state = (state_t*)output;

  g_key = key;
  key_expansion();

  // The next function call encrypts the PlainText with the Key using AES.
  do_cipher();
}

void decrypt_aes128_ecb(uint8_t* input, const uint8_t* key, uint8_t* output) {
  // Copy input to output, and work in-memory on output
  block_copy(output, input);
  g_state = (state_t*)output;

  // The key_expansion routine must be called before encryption.
  g_key = key;
  key_expansion();

  do_inv_cipher();
}

JHANDLER_FUNCTION(Encrypt) {
  JHANDLER_CHECK_ARGS(2, object, object);

  // 1st argument: input (Buffer object)
  const iotjs_jval_t* input = JHANDLER_GET_ARG(0, object);
  iotjs_bufferwrap_t* input_buffer_wrap = iotjs_bufferwrap_from_jbuffer(input);
  uint8_t* input_array = (uint8_t*)iotjs_bufferwrap_buffer(input_buffer_wrap);

  // 2nd arguement: key (Buffer object)
  const iotjs_jval_t* key = JHANDLER_GET_ARG(1, object);
  iotjs_bufferwrap_t* key_buffer_wrap = iotjs_bufferwrap_from_jbuffer(key);
  uint8_t* key_array = (uint8_t*)iotjs_bufferwrap_buffer(key_buffer_wrap);

  // Return value: output (Buffer object)
  size_t input_length = iotjs_bufferwrap_length(input_buffer_wrap);
  iotjs_jval_t output_jbuffer = iotjs_bufferwrap_create_buffer(input_length);
  iotjs_bufferwrap_t* output_buffer_wrap =
      iotjs_bufferwrap_from_jbuffer(&output_jbuffer);
  uint8_t* output_array = (uint8_t*)iotjs_bufferwrap_buffer(output_buffer_wrap);

  // Encrypt Logic
  encrypt_aes128_ecb(input_array, key_array, output_array);

  // Return output!
  iotjs_jhandler_return_jval(jhandler, &output_jbuffer);
  iotjs_jval_destroy(&output_jbuffer);
}

JHANDLER_FUNCTION(Decrypt) {
  JHANDLER_CHECK_ARGS(2, object, object);

  // 1st argument: input (Buffer object)
  const iotjs_jval_t* input = JHANDLER_GET_ARG(0, object);
  iotjs_bufferwrap_t* input_buffer_wrap = iotjs_bufferwrap_from_jbuffer(input);
  uint8_t* input_array = (uint8_t*)iotjs_bufferwrap_buffer(input_buffer_wrap);

  // 2nd arguement: key (Buffer object)
  const iotjs_jval_t* key = JHANDLER_GET_ARG(1, object);
  iotjs_bufferwrap_t* key_buffer_wrap = iotjs_bufferwrap_from_jbuffer(key);
  uint8_t* key_array = (uint8_t*)iotjs_bufferwrap_buffer(key_buffer_wrap);

  // Return value: output (Buffer object)
  size_t input_length = iotjs_bufferwrap_length(input_buffer_wrap);
  iotjs_jval_t output_jbuffer = iotjs_bufferwrap_create_buffer(input_length);
  iotjs_bufferwrap_t* output_buffer_wrap =
      iotjs_bufferwrap_from_jbuffer(&output_jbuffer);
  uint8_t* output_array = (uint8_t*)iotjs_bufferwrap_buffer(output_buffer_wrap);

  // Decrypt Logic
  decrypt_aes128_ecb(input_array, key_array, output_array);

  // Return output!
  iotjs_jhandler_return_jval(jhandler, &output_jbuffer);
  iotjs_jval_destroy(&output_jbuffer);
}

iotjs_jval_t InitCipher() {
  iotjs_jval_t cipher = iotjs_jval_create_object();

  iotjs_jval_set_method(&cipher, "encrypt", Encrypt);
  iotjs_jval_set_method(&cipher, "decrypt", Decrypt);

  return cipher;
}
