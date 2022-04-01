#include "aes.h"
extern void __attribute__((noreturn)) wbpf_host_complete();

void __attribute__((noreturn)) do_encrypt(uint8_t *buffer, size_t bufferSize, uint8_t *key, uint8_t *iv)
{
  struct AES_ctx ctx;

  AES_init_ctx_iv(&ctx, key, iv);
  AES_CBC_encrypt_buffer(&ctx, buffer, bufferSize);
  wbpf_host_complete();
}
