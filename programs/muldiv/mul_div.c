extern void __attribute__((noreturn)) wbpf_host_complete();

/*void mul_div_s(long a, long b, long *out_mul, long *out_div, long *out_mod) {
  *out_mul = a * b;
  *out_div = a / b;
  *out_mod = a % b;
}*/

void __attribute__((noreturn)) mul_div_u(unsigned long a, unsigned long b, unsigned long *out_mul, unsigned long *out_div, unsigned long *out_mod) {
  *out_mul = a * b;
  *out_div = a / b;
  *out_mod = a % b;
  wbpf_host_complete();
}
