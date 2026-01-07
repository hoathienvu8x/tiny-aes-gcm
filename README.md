# Tiny AES GCM

## Strutures

```c
typedef struct {
  uint32_t round_keys[60];
  int rounds;
  uint8_t H[AES_BLOCK_SIZE];
  const uint8_t *iv;
  size_t iv_len;
  const uint8_t *aad;
  size_t aad_len;
} aes_gcm_context;
```

## APIs

```c
void aes_gcm_init(aes_gcm_context *ctx, const uint8_t *key, int key_bits);

void aes_gcm_set_iv(aes_gcm_context *ctx, const uint8_t *iv, size_t iv_len);
void aes_gcm_set_aad(aes_gcm_context *ctx, const uint8_t *aad, size_t aad_len);

extern int generate_random_bytes(uint8_t *buffer, size_t len);
int aes_gcm_generate_iv(uint8_t *iv);
int aes_gcm_generate_key(uint8_t *key, int key_bits);

int aes_gcm_encrypt(
  aes_gcm_context *ctx,
  const uint8_t *input, size_t length,
  uint8_t *output, uint8_t *tag
);

int aes_gcm_decrypt(
  aes_gcm_context *ctx,
  const uint8_t *input, size_t length,
  const uint8_t *tag, uint8_t *output
);

int aes_gcm_string_encrypt(
  aes_gcm_context *ctx,
  const char *input_str, size_t len,
  uint8_t **output_cipher, size_t *cipher_len, uint8_t *output_tag
);

int aes_gcm_string_decrypt(
  aes_gcm_context *ctx,
  const uint8_t *input_cipher, size_t cipher_len,
  const uint8_t *input_tag, char **output_str
);
```
