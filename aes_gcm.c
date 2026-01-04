#include <stdlib.h>
#include <stdio.h>

#include "aes_gcm.h"

static int aes_gcm_process(
  aes_gcm_context *ctx, const uint8_t *iv, size_t iv_len,
  const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t length,
  uint8_t *output, uint8_t *tag, int encrypt
) {
  (void)ctx;
  (void)iv;
  (void)iv_len;
  (void)aad;
  (void)aad_len;
  (void)input;
  (void)length;
  (void)output;
  (void)tag;
  (void)encrypt;
  return -1;  
}
static int generate_random_bytes(uint8_t *buffer, size_t len) {
  size_t read_len;
  FILE *fp = fopen("/dev/urandom", "rb");
  if (!fp) return -1;
  
  read_len = fread(buffer, 1, len, fp);
  fclose(fp);
  
  return (read_len == len) ? 0 : -1;
}
void aes_gcm_init(aes_gcm_context *ctx, const uint8_t *key, int key_bits) {
  /* TODO: AES GCM Init*/
  (void)ctx;
  (void)key;
  (void)key_bits;
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
  uint8_t computed_tag[GCM_TAG_SIZE];
  (void)tag;
  return aes_gcm_process(
    ctx, iv, iv_len, aad, aad_len, input, length, output, computed_tag, 0
  );
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
