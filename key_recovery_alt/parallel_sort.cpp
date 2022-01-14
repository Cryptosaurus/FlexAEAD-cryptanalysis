// Parallel sort using glibc parallel interface

#include <stdint.h>
#include <stdlib.h>
#include <algorithm>
#include <parallel/algorithm>

extern "C" {
  typedef struct {
    uint64_t C;
    uint64_t N:63, t:1;
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


// Disk-based large-data sort using stxxl
#include <vector>
#include <stxxl/sorter>

struct my_comparator
{
  bool operator () (const data_t& A, const data_t& B) const {
    return (A.C < B.C);
  }
  data_t min_value() const {
    return (data_t){0, 0, 0};
  }
  data_t max_value() const {
    return (data_t){(uint64_t)-1LL, 0, 0};
  }
};

typedef stxxl::sorter<data_t, my_comparator> sorter_type;

extern "C" {
  void sort_data_large(data_t *d, uint64_t N) {
    sorter_type candidate_sorter(my_comparator(), 64 * 1024 * 1024 * 1024ULL);
  
    for (size_t i=0; i<N; i++)
      candidate_sorter.push(d[i]);
  
    candidate_sorter.sort();
  
    for (size_t i=0; i<N; i++) {
      d[i] = *candidate_sorter;
      ++candidate_sorter;
    }
    return;
  }
}
