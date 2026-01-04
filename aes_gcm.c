#include "aes_gcm.h"

void aes_gcm_init(aes_gcm_context *ctx, const uint8_t *key, int key_bits) {
  /* TODO: AES GCM Init*/
  (void)ctx;
  (void)key;
  (void)key_bits;
}
int aes_gcm_generate_iv(uint8_t *iv) {
  /* TODO: Random iv */
  (void)iv;
  return -1;
}
int aes_gcm_generate_key(uint8_t *key, int key_bits) {
  /* TODO: Random key */
  (void)key;
  (void)key_bits;
  return -1;
}
int aes_gcm_encrypt(
  aes_gcm_context *ctx, const uint8_t *iv, size_t iv_len,
  const uint8_t *aad, size_t aad_len,
  const uint8_t *input, size_t length,
  uint8_t *output, uint8_t *tag
) {
  /* TODO: AES GCM encrypt fixed length */
  (void)ctx;
  (void)iv;
  (void)iv_len;
  (void)aad;
  (void)aad_len;
  (void)input;
  (void)length;
  (void)output;
  (void)tag;
  return -1;
}
int aes_gcm_decrypt(
  aes_gcm_context *ctx, const uint8_t *iv, size_t iv_len,
  const uint8_t *aad, size_t aad_len,
  const uint8_t *input, size_t length,
  const uint8_t *tag, uint8_t *output
) {
  /* TODO: AES GCM decrypt fixed length */
  (void)ctx;
  (void)iv;
  (void)iv_len;
  (void)aad;
  (void)aad_len;
  (void)input;
  (void)length;
  (void)tag;
  (void)output;
  return -1;
}
int aes_gcm_string_encrypt(
  aes_gcm_context *ctx, const uint8_t *iv,
  const char *input_str, size_t len,
  uint8_t **output_cipher, size_t *cipher_len, uint8_t *output_tag
) {
  /* TODO: AES GCM encrypt string input */
  (void)ctx;
  (void)iv;
  (void)input_str;
  (void)len;
  (void)output_cipher;
  (void)cipher_len;
  (void)output_tag;
  return -1;
}
int aes_gcm_string_decrypt(
  aes_gcm_context *ctx, const uint8_t *iv,
  const uint8_t *input_cipher, size_t cipher_len,
  const uint8_t *input_tag, char **output_str
) {
  /* TODO: AES GCM decrypt string input */
  (void)ctx;
  (void)iv;
  (void)input_cipher;
  (void)cipher_len;
  (void)input_tag;
  (void)output_str;
  return -1;
}
