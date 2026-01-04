#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "aes_gcm.h"

int generate_random_bytes(uint8_t *buffer, size_t len) {
  size_t read_len;
  FILE *fp = fopen("/dev/urandom", "rb");
  if (!fp) return -1;
  
  read_len = fread(buffer, 1, len, fp);
  fclose(fp);
  
  return (read_len == len) ? 0 : -1;
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

void run_random_test(int key_bits, size_t aad_len, size_t pt_len) {
  int rc = -1;
  size_t i;
  aes_gcm_context ctx;

  uint8_t key[32];
  uint8_t iv[GCM_IV_SIZE];
  uint8_t tag[GCM_TAG_SIZE];

  uint8_t *aad = NULL, *pt = NULL, *ct = NULL, *out = NULL;

  printf("--- RANDOM TEST: AES-%d-GCM ---\n", key_bits);
  printf(
    "Config: AAD=%ld bytes, PT=%ld bytes, IV=%d bytes\n",
    aad_len, pt_len, GCM_IV_SIZE
  );

  if (aad_len > 0) aad = malloc(aad_len);
  pt = malloc(pt_len);
  ct = malloc(pt_len);
  out = malloc(pt_len);

  if (!pt || !ct || !out) goto done;

  srand(time(NULL));
  for (i = 0; i < 32; i++) {
    key[i] = rand() % 256;
  }
  for (i = 0; i < GCM_IV_SIZE; i++) {
    iv[i] = rand() % 256;
  }
  if (aad_len > 0) {
    for (i = 0; i < aad_len; i++) {
      aad[i] = rand() % 256;
    }
  }
  for (i = 0; i < pt_len; i++) {
    pt[i] = rand() % 256;
  }

  hex_dump("Key", key, key_bits / 8);
  hex_dump("IV", iv, GCM_IV_SIZE);
  if (aad_len > 0) hex_dump("AAD", aad, aad_len);
  hex_dump("Plaintext", pt, pt_len);

  aes_gcm_init(&ctx, key, key_bits);
  if (aes_gcm_encrypt(
    &ctx, iv, GCM_IV_SIZE, aad, aad_len, pt, pt_len, ct, tag
  )) {
    goto done;
  }

  hex_dump("Ciphertext", ct, pt_len);
  hex_dump("Auth Tag", tag, GCM_TAG_SIZE);

  rc = aes_gcm_decrypt(
    &ctx, iv, GCM_IV_SIZE, aad, aad_len, ct, pt_len, tag, out
  );

  if (rc != 0 || memcmp(pt, out, pt_len) != 0) {
    printf("RANDOM TEST RESULT: FAILED!\n");
    if (rc != 0) {
      printf("Reason: Authentication tag mismatch.\n");
    } else {
      printf("Reason: Plaintext mismatch.\n");
    }
  } else {
    printf("RANDOM TEST RESULT: PASSED (Integrity & Decryption OK)\n");
    hex_dump("Decrypted Output", out, pt_len);
  }
  printf("\n");

done:
  free(aad);
  free(pt);
  free(ct);
  free(out);
}

int main(int argc, char **argv) {
  aes_gcm_context ctx;
  uint8_t key[32], iv[GCM_IV_SIZE], tag[GCM_TAG_SIZE], *cipher = NULL;
  size_t cipher_len = 0;
  char *decrypted = NULL;
  const char *msg = NULL;

  if (argc < 2) {
    run_random_test(128, 13, 27);
    run_random_test(256, 50, 100);
    run_random_test(256, 0, 1024);
    return 0;
  }

  msg = argv[1];
  if (aes_gcm_generate_key(key, 256) || aes_gcm_generate_iv(iv)) {
    return -1;
  }

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
