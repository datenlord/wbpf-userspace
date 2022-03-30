#include <stdint.h>

long callByName(const char *name);
int extAdd(int a, int b);

static uint64_t data[] = {0x1111, 0x2222, 0x99};

long entry() {
    return callByName("test") + callByName("test2") + 1;
}

void set_data(int index, uint64_t value) {
    data[index] = value;
}

uint64_t get_data(int index) {
    return data[index];
}

static __attribute__((noinline)) int add(int a, int b) {
    return a + b;
}

int callAddPlusOne(int a, int b) {
    return add(a, b) + extAdd(a, b) + 1;
}

