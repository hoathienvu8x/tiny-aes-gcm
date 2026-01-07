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

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Giả định các cấu trúc và hàm đã được định nghĩa trong thư viện của bạn
struct aes_ctx_t; 

void print_hex(const char *label, const uint8_t *data, size_t len) {
  printf("%s: ", label);
  for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
  printf("\n");
}

int main() {
  // 1. Khởi tạo thực thể Alice và Bob
  uint8_t alice_priv[32], alice_pub[64];
  uint8_t bob_priv[32], bob_pub[64];
    
  p256_gen_keypair(alice_priv, alice_pub);
  p256_gen_keypair(bob_priv, bob_pub);

  printf("--- Khoi tao khoa ---\n");
  print_hex("Alice Public Key", alice_pub, 64);
  print_hex("Bob Public Key", bob_pub, 64);

  // 2. Tinh toan Shared Secret (ECDH)
  uint8_t alice_shared[32];
  uint8_t bob_shared[32];

  p256_ecdh_shared_secret(alice_shared, alice_priv, bob_pub);
  p256_ecdh_shared_secret(bob_shared, bob_priv, alice_pub);

  // 3. Alice chuan bi gui tin nhan
  const char *msg = "Xin chao Bob, day la tin nhan bao mat!";
  size_t msg_len = strlen(msg);
  printf("\n--- Alice gui tin nhan ---\nContent: %s\n", msg);

  // Ky tin nhan (ECDSA)
  uint8_t hash[32];
  uint8_t signature[64];
  sha256(msg, msg_len, hash);
  p256_ecdsa_sign(signature, alice_priv, hash, 32);

  // Ma hoa tin nhan (AES)
  struct aes_ctx_t ctx;
  uint8_t iv[16];
  p256_generate_random(iv, 16); // Tao IV ngau nhien

  aes_init(&ctx, alice_shared, 256);
  aes_set_iv(&ctx, iv, 16);
    
  uint8_t *ciphertext = NULL;
  size_t *cipher_len = NULL;
  aes_message_encrypt(&ctx, (uint8_t*)msg, msg_len, &ciphertext, &cipher_len);

  print_hex("Ciphertext", ciphertext, (size_t)cipher_len);
  print_hex("Signature", signature, 64);

  // 4. Bob nhan va giai ma
  printf("\n--- Bob nhan tin nhan ---\n");
    
  struct aes_ctx_t rx_ctx;
  uint8_t *decrypted_msg = NULL;
  size_t *decrypted_len = NULL;

  aes_init(&rx_ctx, bob_shared, 256);
  aes_set_iv(&rx_ctx, iv, 16); // Bob su dung cung IV ma Alice da gui kem
    
  if (aes_message_decrypt(&rx_ctx, ciphertext, (size_t)cipher_len, &decrypted_msg, &decrypted_len) == 0) {
    printf("Giai ma thanh cong: %s\n", (char*)decrypted_msg);

    // Xac thuc chu ky
    uint8_t rx_hash[32];
    sha256(decrypted_msg, (size_t)decrypted_len, rx_hash);

    if (p256_ecdsa_verify(signature, alice_pub, rx_hash, 32) == 0) {
      printf("Xac thuc chu ky: THANH CONG (Tin nhan tu Alice)\n");
    } else {
      printf("Xac thuc chu ky: THAT BAI!\n");
    }
  } else {
    printf("Giai ma that bai!\n");
  }

  // Giai phong bo nho neu API co thuc hien malloc ben trong
  free(ciphertext);
  free(decrypted_msg);

  return 0;
}
```
