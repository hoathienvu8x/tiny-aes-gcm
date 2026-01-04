#ifndef AES_GCM_H
#define AES_GCM_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16
#define GCM_TAG_SIZE   16
#ifndef GCM_IV_SIZE
  #define GCM_IV_SIZE  12
#endif

typedef struct {
  uint32_t round_keys[60];
  int rounds;
  uint8_t H[AES_BLOCK_SIZE];
} aes_gcm_context;

void aes_gcm_init(aes_gcm_context *ctx, const uint8_t *key, int key_bits);
int aes_gcm_generate_iv(uint8_t *iv);
int aes_gcm_generate_key(uint8_t *key, int key_bits);
int aes_gcm_encrypt(
  aes_gcm_context *ctx, const uint8_t *iv, size_t iv_len,
  const uint8_t *aad, size_t aad_len,
  const uint8_t *input, size_t length,
  uint8_t *output, uint8_t *tag
);
int aes_gcm_decrypt(
  aes_gcm_context *ctx, const uint8_t *iv, size_t iv_len,
  const uint8_t *aad, size_t aad_len,
  const uint8_t *input, size_t length,
  const uint8_t *tag, uint8_t *output
);
int aes_gcm_string_encrypt(
  aes_gcm_context *ctx, const uint8_t *iv,
  const char *input_str, size_t len,
  uint8_t **output_cipher, size_t *cipher_len, uint8_t *output_tag
);
int aes_gcm_string_decrypt(
  aes_gcm_context *ctx, const uint8_t *iv,
  const uint8_t *input_cipher, size_t cipher_len,
  const uint8_t *input_tag, char **output_str
);

#endif
