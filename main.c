#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "aes_gcm.h"
#include "p256-m.h"
#include "sha256.h"

int generate_random_bytes(uint8_t *buffer, size_t len) {
  size_t read_len;
  FILE *fp = fopen("/dev/urandom", "rb");
  if (!fp) return -1;
  
  read_len = fread(buffer, 1, len, fp);
  fclose(fp);
  
  return (read_len == len) ? 0 : -1;
}

int p256_generate_random(uint8_t * output, unsigned output_size) {
  return generate_random_bytes(output, output_size);
}

static void hex_dump(const char *label, const uint8_t *buf, size_t len) {
  size_t i;
  printf("%s (%ld bytes):\n", label, len);
  for (i = 0; i < len; i++) {
    printf("%02x", buf[i]);
    if ((i & 15) == 15) printf("\n");
  }
  if (i & 15) printf("\n");
}

int main(int argc, char **argv) {
  aes_gcm_context ctx;
  uint8_t privR[32], pubR[64];
  uint8_t privE[32], pubE[64];
  uint8_t shared[32], key[32], iv[GCM_IV_SIZE], tag[GCM_TAG_SIZE], *cipher = NULL;

  size_t cipher_len = 0;
  char *decrypted = NULL;
  const char *msg = NULL;

  if (
    p256_gen_keypair(privR, pubR) ||
    p256_gen_keypair(privE, pubE)
  ) {
    return -1;
  }
  if (!p256_ecdh_shared_secret(pubR, privE, shared)) {
    return -1;
  }
  sha256(shared, sizeof(shared), key);
  sha256(pubE, sizeof(pubE), shared);
  memcpy(iv, shared, GCM_IV_SIZE);;

  if (argc < 2) {
    return 0;
  }

  msg = argv[1];

  hex_dump("Key ", key, 32);
  hex_dump("Iv", iv, GCM_IV_SIZE);

  aes_gcm_init(&ctx, key, 256);
  if (aes_gcm_string_encrypt(
    &ctx, iv, msg, strlen(msg), &cipher, &cipher_len, tag
  )) {
    return -1;
  }

  hex_dump("Ciphertext", cipher, cipher_len);
  hex_dump("Auth tag", tag, GCM_TAG_SIZE);

  if (p256_ecdh_shared_secret(pubE, privR, shared)) {
    free(cipher);
    return -1;
  }
  sha256(shared, sizeof(shared), key);
  if (aes_gcm_string_decrypt(
    &ctx, iv, cipher, cipher_len, tag, &decrypted
  ) == 0) {
    if (strcmp(msg, decrypted) == 0) {
      printf("Ok\n");
    } else {
      printf("%s (Failed)\n", decrypted);
    }
  }
  free(cipher);
  if (decrypted) free(decrypted);
  return 0;
}
