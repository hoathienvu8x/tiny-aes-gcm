#include <stdlib.h>
#include <string.h>

#include "aes_gcm.h"

static const uint8_t sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
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
  0xb0, 0x54, 0xbb, 0x16
};
static const uint32_t rcon[] = {
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};
static uint32_t rot_word(uint32_t w) {
  return (w << 8) | (w >> 24);
}
static uint32_t sub_word(uint32_t w) {
  return (
    (uint32_t)sbox[(w >> 24) & 0xFF] << 24 |
    (uint32_t)sbox[(w >> 16) & 0xFF] << 16 |
    (uint32_t)sbox[(w >> 8) & 0xFF] << 8 |
    (uint32_t)sbox[w & 0xFF]
  );
}
#define xtime(x) ((x << 1) ^ (((x >> 7) & 1) * 0x1b))

static void mix_columns(uint8_t state[AES_BLOCK_SIZE]) {
  int i;
  for (i = 0; i < AES_BLOCK_SIZE; i += 4) {
    uint8_t a = state[i], b = state[i + 1];
    uint8_t c = state[i + 2], d = state[i + 3];
    uint8_t  h = a ^ b ^ c ^ d;
    state[i]   ^= h ^ xtime(a ^ b);
    state[i + 1] ^= h ^ xtime(b ^ c);
    state[i + 2] ^= h ^ xtime(c ^ d);
    state[i + 3] ^= h ^ xtime(d ^ a);
  }
}
static void aes_encrypt_block(
  const uint8_t in[AES_BLOCK_SIZE], const uint32_t *rk,
  int rounds, uint8_t out[AES_BLOCK_SIZE]
) {
  int i, r;
  uint8_t s[AES_BLOCK_SIZE], t[AES_BLOCK_SIZE];
  memcpy(s, in, AES_BLOCK_SIZE);
  for (r = 0; ; r++) {
    for (i = 0; i < 4; i++) {
      s[i * 4] ^= (rk[r * 4 + i] >> 24);
      s[i * 4 + 1] ^= (rk[r * 4 + i] >> 16);
      s[i * 4 + 2] ^= (rk[r * 4 + i] >> 8);
      s[i * 4 + 3] ^= rk[r * 4 + i];
    }
    if (r == rounds) break;
    for (i = 0; i < AES_BLOCK_SIZE; i++) {
      s[i] = sbox[s[i]];
    }
    memcpy(t, s, AES_BLOCK_SIZE);
    s[1] = t[5]; s[5] = t[9]; s[9] = t[13]; s[13] = t[1];
    s[2] = t[10]; s[10] = t[2];
    s[6] = t[14]; s[14] = t[6];
    s[3] = t[15]; s[7] = t[3]; s[11] = t[7]; s[15] = t[11];

    if (r < rounds - 1) {
      mix_columns(s);
    }
  }
  memcpy(out, s, AES_BLOCK_SIZE);
}
static void gfm_multiply(uint8_t *x, const uint8_t *y) {
  uint8_t res[AES_BLOCK_SIZE] = {0};
  uint8_t v[AES_BLOCK_SIZE];
  int i, j, carry;
  memcpy(v, y, AES_BLOCK_SIZE);
  for (i = 0; i < 128; i++) {
    if ((x[i / 8] >> (7 - (i % 8))) & 1) {
      for (j = 0; j < AES_BLOCK_SIZE; j++) {
        res[j] ^= v[j];
      }
    }
    carry = v[15] & 1;
    for (j = 15; j > 0; j--) {
      v[j] = (v[j] >> 1) | (v[j - 1] << 7);
    }
    v[0] >>= 1;
    if (carry) {
      v[0] ^= 0xe1;
    }
  }
  memcpy(x, res, AES_BLOCK_SIZE);
}

static void ghash_update(
  uint8_t y[AES_BLOCK_SIZE], const uint8_t h[AES_BLOCK_SIZE],
  const uint8_t *block, size_t len
) {
  int i;
  uint8_t tmp[AES_BLOCK_SIZE] = {0};
  memcpy(tmp, block, len);
  for (i = 0; i < AES_BLOCK_SIZE; i++) {
    y[i] ^= tmp[i];
  }
  gfm_multiply(y, h);
}
static void compute_j0(
  const uint8_t *h, const uint8_t *iv,
  size_t iv_len, uint8_t j0[AES_BLOCK_SIZE]
) {
  size_t i;
  if (iv_len == 12) {
    memcpy(j0, iv, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
  } else {
    uint64_t iv_bits = 0;
    uint8_t y[AES_BLOCK_SIZE] = {0};
    uint8_t lb[AES_BLOCK_SIZE] = {0};
    for (i = 0; i < iv_len; i += AES_BLOCK_SIZE) {
      ghash_update(
        y, h, iv + i,
        (iv_len - i) < AES_BLOCK_SIZE ? (iv_len - i) : AES_BLOCK_SIZE);
    }
    iv_bits = (uint64_t)iv_len * 8;
    for (i = 0; i < 8; i++) {
      lb[15-i] = (uint8_t)(iv_bits >> (i * 8));
    }
    ghash_update(y, h, lb, AES_BLOCK_SIZE);
    memcpy(j0, y, AES_BLOCK_SIZE);
  }
}
static int aes_gcm_process(
  aes_gcm_context *ctx, const uint8_t *iv, size_t iv_len,
  const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t length,
  uint8_t *output, uint8_t *tag, int encrypt
) {
  uint8_t j0[AES_BLOCK_SIZE], ctr[AES_BLOCK_SIZE], mask[AES_BLOCK_SIZE];
  uint8_t y[AES_BLOCK_SIZE] = {0}, lb[AES_BLOCK_SIZE] = {0};
  size_t i, j, chunk;
  uint64_t al_bits, cl_bits;

  if (!ctx || !iv || (length > 0 && (!input || !output)) || !tag) {
    return -1;
  }
  compute_j0(ctx->H, iv, iv_len, j0);
  for (i = 0; i < aad_len; i += AES_BLOCK_SIZE) {
    ghash_update(
      y, ctx->H, aad + i,
      (aad_len - i) < AES_BLOCK_SIZE ? (aad_len - i) : AES_BLOCK_SIZE
    );
  }

  memcpy(ctr, j0, AES_BLOCK_SIZE);
  for (i = 0; i < length; i += AES_BLOCK_SIZE) {
    for (j = 15; j >= 12; j--) {
      if (++ctr[j]) break;
    }
    
    aes_encrypt_block(ctr, ctx->round_keys, ctx->rounds, mask);
    chunk = (length - i) < AES_BLOCK_SIZE ? (length - i) : AES_BLOCK_SIZE;
    
    if (encrypt) {
      for (j = 0; j < chunk; j++) {
        output[i+j] = input[i+j] ^ mask[j];
      }
      ghash_update(y, ctx->H, output + i, chunk);
    } else {
      ghash_update(y, ctx->H, input + i, chunk);
      for (j = 0; j < chunk; j++) {
        output[i+j] = input[i+j] ^ mask[j];
      }
    }
  }

  al_bits = (uint64_t)aad_len * 8;
  cl_bits = (uint64_t)length * 8;
  for (i = 0; i < 8; i++) {
    lb[7 - i] = (uint8_t)(al_bits >> (i * 8));
    lb[15 - i] = (uint8_t)(cl_bits >> (i * 8));
  }
  ghash_update(y, ctx->H, lb, AES_BLOCK_SIZE);

  aes_encrypt_block(j0, ctx->round_keys, ctx->rounds, mask);
  for (i = 0; i < GCM_TAG_SIZE; i++) {
    tag[i] = y[i] ^ mask[i];
  }

  return 0; 
}
/*********************** PUBLIC APIS ***********************************/
void aes_gcm_init(aes_gcm_context *ctx, const uint8_t *key, int key_bits) {
  int i, nk = key_bits / 32;
  uint8_t zero[AES_BLOCK_SIZE] = {0};
  ctx->rounds = nk + 6;
  for (i = 0; i < nk; i++) {
    ctx->round_keys[i] = (
      (uint32_t)key[4 * i] << 24 | (uint32_t)key[4 * i + 1] << 16 |
      (uint32_t)key[4 * i + 2] << 8 | (uint32_t)key[4 * i + 3]
    );
  }
  for (i = nk; i < (ctx->rounds + 1) * 4; i++) {
    uint32_t temp = ctx->round_keys[i - 1];
    if (i % nk == 0) {
      temp = sub_word(rot_word(temp)) ^ rcon[(i / nk) - 1];
    } else if (nk > 6 && (i % nk == 4)) {
      temp = sub_word(temp);
    }
    ctx->round_keys[i] = ctx->round_keys[i - nk] ^ temp;
  }
  aes_encrypt_block(zero, ctx->round_keys, ctx->rounds, ctx->H);
}
int aes_gcm_generate_iv(uint8_t *iv) {
  return generate_random_bytes(iv, GCM_IV_SIZE);
}
int aes_gcm_generate_key(uint8_t *key, int key_bits) {
  if (key_bits != 128 && key_bits != 192 && key_bits != 256) return -1;
  return generate_random_bytes(key, key_bits / 8);
}
int aes_gcm_encrypt(
  aes_gcm_context *ctx, const uint8_t *iv, size_t iv_len,
  const uint8_t *aad, size_t aad_len,
  const uint8_t *input, size_t length,
  uint8_t *output, uint8_t *tag
) {
  return aes_gcm_process(
    ctx, iv, iv_len, aad, aad_len, input, length, output, tag, 1
  );
}
int aes_gcm_decrypt(
  aes_gcm_context *ctx, const uint8_t *iv, size_t iv_len,
  const uint8_t *aad, size_t aad_len,
  const uint8_t *input, size_t length,
  const uint8_t *tag, uint8_t *output
) {
  int i, diff = 0;
  uint8_t computed_tag[GCM_TAG_SIZE];
  if (aes_gcm_process(
    ctx, iv, iv_len, aad, aad_len, input,
    length, output, computed_tag, 0
  ) != 0) {
    return -1;
  }

  for (i = 0; i < GCM_TAG_SIZE; i++) {
    diff |= (computed_tag[i] ^ tag[i]);
  }

  if (diff != 0) {
    memset(output, 0, length);
    return -1;
  }

  return 0;
}
int aes_gcm_string_encrypt(
  aes_gcm_context *ctx, const uint8_t *iv,
  const char *input_str, size_t len,
  uint8_t **output_cipher, size_t *cipher_len, uint8_t *output_tag
) {
  *cipher_len = 0;
  if (!input_str || len == 0 || !output_cipher || !output_tag) {
    return -1;
  }
  *output_cipher = (uint8_t *)malloc(len);
  if (*output_cipher == NULL) return -2;

  if (aes_gcm_encrypt(
    ctx, iv, GCM_IV_SIZE, NULL, 0, (const uint8_t*)input_str,
    len, *output_cipher, output_tag
  ) == 0) {
    *cipher_len = len;
    return 0;
  }
  free(*output_cipher);
  *output_cipher = NULL;
  return -1;
}
int aes_gcm_string_decrypt(
  aes_gcm_context *ctx, const uint8_t *iv,
  const uint8_t *input_cipher, size_t cipher_len,
  const uint8_t *input_tag, char **output_str
) {
  if (!input_cipher || !output_str || !input_tag) return -1;
  *output_str = (char *)malloc(cipher_len + 1);
  if (*output_str == NULL) return -2;
  
  if (aes_gcm_decrypt(
    ctx, iv, GCM_IV_SIZE, NULL, 0, input_cipher, cipher_len,
    input_tag, (uint8_t*)*output_str
  ) == 0) {
    (*output_str)[cipher_len] = '\0';
    return 0;
  }
  free(*output_str);
  *output_str = NULL;
  return -1;
}
