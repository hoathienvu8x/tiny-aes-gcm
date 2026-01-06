#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes_gcm.h"

int generate_random_bytes(uint8_t *buffer, size_t len) {
  size_t read_len;
  FILE *fp = fopen("/dev/urandom", "rb");
  if (!fp) return -1;
  
  read_len = fread(buffer, 1, len, fp);
  fclose(fp);
  
  return (read_len == len) ? 0 : -1;
}

void print_hex(const char *label, const uint8_t *data, size_t len) {
  size_t i;
  printf("%s: ", label);
  for (i = 0; i < len; i++) {
    printf("%02x", data[i]);
  }
  printf("\n");
}

void usage(const char *prog_name) {
  printf("Sử dụng CLI AES-GCM (Hỗ trợ AAD):\n");
  printf("  Tạo Key : %s gen <key_bits>\n", prog_name);
  printf("  Mã hóa: %s enc <key_hex> <plain_text> [aad_text]\n", prog_name);
  printf("  Giải mã: %s dec <key_hex> <iv_hex> <tag_hex> <cipher_hex> [aad_text]\n", prog_name);
  printf(
    "\nLưu ý:\n  key phải là 16, 24 hoặc 32 bytes (32, 48, hoặc 64 ký tự"
    " hex).\n  <key_bits> thường là 128, 192 hoặc 256.\n"
  );
}

int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len) {
  size_t i, len = strlen(hex);
  if (len % 2 != 0 || len / 2 > max_len) return -1;
  for (i = 0; i < len / 2; i++) {
    unsigned int temp;
    if (sscanf(hex + 2 * i, "%02x", &temp) != 1) {
      return -1;
    }
    bytes[i] = (uint8_t)temp;
  }
  return (int)(len / 2);
}

int main(int argc, char *argv[]) {
  int key_len;
  const char *mode;
  aes_gcm_context ctx;
  uint8_t key[32];

  if (argc < 2) {
    usage(argv[0]);
    return 1;
  }

  mode = argv[1];

  if (strcmp(mode, "gen") == 0) {
    int bits = (argc > 2) ? atoi(argv[2]) : 256;
    uint8_t key[32];
    if (bits != 128 && bits != 192 && bits != 256) {
      fprintf(stderr, "Lỗi: Key bits phải là 128, 192 hoặc 256.\n");
      return 1;
    }
    if (aes_gcm_generate_key(key, bits) == 0) {
      print_hex("Generated Key", key, bits / 8);
    } else {
      fprintf(stderr, "Lỗi khi tạo key.\n");
    }
    return 0;
  }
  if (argc < 4) {
    usage(argv[0]);
    return 1;
  }

  key_len = hex_to_bytes(argv[2], key, 32);

  if (key_len <= 0) {
    fprintf(stderr, "Lỗi: Key không hợp lệ.\n");
    return 1;
  }

  aes_gcm_init(&ctx, key, key_len * 8);

  if (strcmp(mode, "enc") == 0) {
    const char *plain_text = argv[3];
    uint8_t iv[GCM_IV_SIZE], tag[GCM_TAG_SIZE];
    uint8_t *cipher = NULL;
    size_t cipher_len = 0;

    aes_gcm_generate_iv(iv);
    aes_gcm_set_iv(&ctx, iv, GCM_IV_SIZE);
    if (argc >= 5) {
      aes_gcm_set_aad(&ctx, (uint8_t *)argv[4], strlen(argv[4]));
    }
    if (aes_gcm_string_encrypt(
      &ctx, plain_text, strlen(plain_text),
      &cipher, &cipher_len, tag
    ) == 0) {
      printf("--- KẾT QUẢ MÃ HÓA ---\n");
      if (argc >= 5) {
        printf("AAD   : %s\n", argv[4]);
      }
      print_hex("IV    ", iv, GCM_IV_SIZE);
      print_hex("Tag   ", tag, GCM_TAG_SIZE);
      print_hex("Cipher", cipher, cipher_len);
      free(cipher);
    } else {
      fprintf(stderr, "Mã hóa thất bại!\n");
    }
  } else if (strcmp(mode, "dec") == 0) {
    uint8_t iv[GCM_IV_SIZE];
    uint8_t tag[GCM_TAG_SIZE];
    uint8_t cipher[1024];
    char *output_str = NULL;
    int iv_len_in, tag_len_in, cipher_len_in;

    if (argc < 6) {
      usage(argv[0]);
      return 1;
    }

    iv_len_in = hex_to_bytes(argv[3], iv, GCM_IV_SIZE);
    tag_len_in = hex_to_bytes(argv[4], tag, GCM_TAG_SIZE);
    cipher_len_in = hex_to_bytes(argv[5], cipher, 1024);

    if (iv_len_in <= 0 || tag_len_in <= 0 || cipher_len_in <= 0) {
      fprintf(stderr, "Lỗi: Dữ liệu đầu vào hex không hợp lệ.\n");
      return 1;
    }
    aes_gcm_set_iv(&ctx, iv, iv_len_in);
    if (argc >= 7) {
      aes_gcm_set_aad(&ctx, (uint8_t *)argv[6], strlen(argv[6]));
    }
    if (aes_gcm_string_decrypt(
      &ctx, cipher, cipher_len_in, tag, &output_str
    ) == 0) {
      printf("--- KẾT QUẢ GIẢI MÃ ---\n");
      printf("Plaintext: %s\n", output_str);
      free(output_str);
    } else {
      fprintf(
        stderr, "Giải mã thất bại! (Sai key, tag, AAD không khớp hoặc dữ"
        " liệu bị sửa đổi)\n"
      );
    }
  } else {
    usage(argv[0]);
  }

  return 0;
}
