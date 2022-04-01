extern void __attribute__((noreturn)) wbpf_host_complete();

void __attribute__((noreturn)) add(int a, int b, int *out) {
  *out = a + b;
  wbpf_host_complete();
}
