extern int wbpf_machine_get_core_index();

int extAdd(int a, int b) {
  return a + b + wbpf_machine_get_core_index();
}
