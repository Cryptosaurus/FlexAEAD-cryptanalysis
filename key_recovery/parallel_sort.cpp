#include <stdint.h>
#include <stdlib.h>
#include <algorithm>
#include <parallel/algorithm>

extern "C" {
  typedef struct {
    uint64_t C;
    uint32_t N:30, t:2;
  } __attribute__((packed)) data_t;
}

extern "C" {
  void sort_data (data_t *d, uint64_t N) {
    __gnu_parallel::sort(d, d+N,
			 [](const data_t &A, const data_t &B){
			   return (A.C < B.C);
			 });
  }

  void sort_data_mask (data_t *d, uint64_t N, uint64_t mask) {
    __gnu_parallel::sort(d, d+N,
			 [=](const data_t &A, const data_t &B){
			   return ((A.C&mask) < (B.C&mask));
			 });
  }
}
