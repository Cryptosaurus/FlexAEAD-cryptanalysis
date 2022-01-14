/********************************************************************
 * Practical key-recovery attack against FlexAEAD-64
 * Variant attack applicable to FlexAE
 *
 * Written in 2020 by Gaëtan Leurent <gaetan.leurent@inria.fr>
 * 
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to
 * the public domain worldwide. This software is distributed without
 * any warranty.
 *
 * http://creativecommons.org/publicdomain/zero/1.0/
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

// Directory for temporary file (8TB needed)
#define DIR "/tmp/"

#include <x86intrin.h>

# include <linux/version.h>
# if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)

#if  (__GLIBC__ > 2) ||  (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)
#include <sys/random.h>
#else
#include <linux/random.h>
#include <sys/syscall.h>
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
  return syscall(SYS_getrandom, buf, buflen, flags);
}
#endif

#else

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
  int fd = open("/dev/urandom", O_RDONLY);
  ssize_t ret = read(fd, buf, buflen);
  close(fd);
  return ret;
}

#endif

#include "encrypt.h"

struct FlexAEADv1 {
   unsigned char subkeys[BLOCKSIZE * 8];
   unsigned char counter[BLOCKSIZE];
   unsigned char checksum[BLOCKSIZE];
   unsigned char state[BLOCKSIZE];
   unsigned char sn[BLOCKSIZE];
   unsigned long long nRounds;
   unsigned long long nBytes;
}; 
int crypto_aead_encrypt(
unsigned char *c,unsigned long long *clen,
const unsigned char *m,unsigned long long mlen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *nsec,
const unsigned char *npub,
struct FlexAEADv1 flexaeadv1
);
void FlexAEADv1_init(struct FlexAEADv1 * self, unsigned char *key );

// Master key
uint8_t Master_K[KEYSIZE];
struct FlexAEADv1 flexAEAD;

#define DATA (1ULL<<28)
#define DATA2 (1ULL<<38)
#define SQRT2 362/256

typedef struct {
  uint64_t C;
  uint64_t N:63, t:1;
} __attribute__((packed)) data_t;

/* void print_diff_pair (data_t a, data_t b); */
int test_K2A (uint64_t K);
int test_K2B3A (uint64_t K, uint64_t S0, uint64_t S1);
int filter_diff_phase1(uint64_t delta);
typedef int (*callback_t)(uint64_t);
uint64_t recover_state (uint64_t S0, uint64_t S1, callback_t filter_diff, callback_t test_state);

int compare_data (const void *a, const void *b) {
  const data_t *A = a;
  const data_t *B = b;
  if (A->C < B->C)
    return -1;
  else if (A->C > B->C)
    return 1;
  else
    return 0;
}
void sort_data (const data_t *d, uint64_t N);
void sort_data_mask (const data_t *d, uint64_t N, uint64_t mask);
void sort_data_large (const data_t *d, uint64_t N);

void make_nonce(uint8_t N[BLOCKSIZE], uint32_t n) {
  for (int i=0; i<8; i++)
    N[i] = ((n>>(4*i))&0xf)<<4;
}

static uint8_t AES_SBOX[] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
#define Sbox(x) AES_SBOX[x]

uint32_t SBOX(uint32_t x) {
  uint32_t y =
     Sbox( x     &0xff)      |
    (Sbox((x>>8 )&0xff)<<8 ) |
    (Sbox((x>>16)&0xff)<<16) |
    (Sbox((x>>24)&0xff)<<24);
  return y;
}

static uint8_t AES_SBOXI[] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
#define SboxI(x) AES_SBOXI[x]

uint32_t SBOXI(uint32_t x) {
  uint32_t y =
     SboxI( x     &0xff)      |
    (SboxI((x>>8 )&0xff)<<8 ) |
    (SboxI((x>>16)&0xff)<<16) |
    (SboxI((x>>24)&0xff)<<24);
  return y;
}

uint64_t round_function(uint64_t x);
uint64_t inverse_round_function(uint64_t x);

// Partial keys recovered
uint64_t K2A;
uint64_t K2B3A;
uint64_t K0B;
uint64_t K0A;
uint64_t K2B;
uint64_t K3B;
uint64_t K2A3B;


int main() {
  uint64_t C[(2*BLOCKSIZE+TAGSIZE)/8];
  unsigned long long clen;
  uint8_t N[BLOCKSIZE] = {0};
  for (int i=0; i<KEYSIZE; i++)
    Master_K[i] = rand();
  
  // Compute subkeys
  FlexAEADv1_init(&flexAEAD, Master_K);
  /* printf ("K3A:   "); */
  /* for (int i=0; i<BLOCKSIZE; i++) */
  /*   printf ("%02x", flexAEAD.subkeys[6*BLOCKSIZE+i]); */
  /* printf ("\n"); */
  printf ("K2A:   ");
  for (int i=0; i<BLOCKSIZE; i++)
    printf ("%02x", flexAEAD.subkeys[4*BLOCKSIZE+i]);
  printf ("\n");
  printf ("K2B3A: ");
  for (int i=0; i<BLOCKSIZE; i++)
    printf ("%02x", flexAEAD.subkeys[5*BLOCKSIZE+i]^flexAEAD.subkeys[6*BLOCKSIZE+i]);
  printf ("\n");
  printf ("K0B:   ");
  for (int i=0; i<BLOCKSIZE; i++)
    printf ("%02x", flexAEAD.subkeys[1*BLOCKSIZE+i]);
  printf ("\n");
  printf ("K0A:   ");
  for (int i=0; i<BLOCKSIZE; i++)
    printf ("%02x", flexAEAD.subkeys[0*BLOCKSIZE+i]);
  printf ("\n");
  printf ("K2B:   ");
  for (int i=0; i<BLOCKSIZE; i++)
    printf ("%02x", flexAEAD.subkeys[5*BLOCKSIZE+i]);
  printf ("\n");
  printf ("K3B:   ");
  for (int i=0; i<BLOCKSIZE; i++)
    printf ("%02x", flexAEAD.subkeys[7*BLOCKSIZE+i]);
  printf ("\n");
  printf ("K2A3B: ");
  for (int i=0; i<BLOCKSIZE; i++)
    printf ("%02x", flexAEAD.subkeys[4*BLOCKSIZE+i]^flexAEAD.subkeys[7*BLOCKSIZE+i]);
  printf ("\n");
  fflush(stdout);
  
  // Hash table
  data_t *data = malloc(2*DATA*sizeof(data_t));
  assert(data);

  printf ("Generate phase 1 data...");
  fflush(stdout);
  // Encrypt zero message with structure of nonces
#pragma omp parallel for private(C) private(clen) firstprivate(N)
  for (unsigned n=0; n<DATA; n++) {
    make_nonce(N, n);
    uint8_t M[2*BLOCKSIZE] = {0};
    crypto_aead_encrypt((uint8_t*)C, &clen, M, sizeof(M), NULL, 0, NULL, N, flexAEAD);
    assert(clen <= sizeof(C));
    data[2*n  ] = (data_t){C: C[0], N: n, t: 0};
    data[2*n+1] = (data_t){C: C[1], N: n, t: 1};
  }
  printf ("Done\n");
  fflush(stdout);

  // Look for collisions
  // qsort(data, 2*DATA, sizeof(data_t), compare_data);
  sort_data(data, 2*DATA);
  int n=0;
  for (unsigned i=1; i<2*DATA; i++)
    if (data[i].C == data[i-1].C)  n++;
  printf ("Found %i collisions\n", n);
  fflush(stdout);

  for (unsigned i=1; i<2*DATA; i++) {
    if (data[i].C == data[i-1].C) {
      assert(data[i].t != data[i-1].t);
      // print_diff_pair(data[i-1], data[i]);
      uint8_t N0[BLOCKSIZE];
      uint8_t N1[BLOCKSIZE];
      make_nonce(N0, data[i-1].N);
      make_nonce(N1, data[i  ].N);
      uint64_t S0 = 0;
      uint64_t S1 = 0;
      for (int i=0; i<BLOCKSIZE; i++) {
	S0 = (S0<<8)^N0[i];
	S1 = (S1<<8)^N1[i];
      }

      int test_key(uint64_t S) {
	return test_K2A(S^S0);
      }

      if (recover_state(S0, S1, filter_diff_phase1, test_key))
	break;
    }
  }

  if (!K2A) {
    printf ("Failed to recover K2A\n");
    exit(0);
  } else {
    printf ("Recovered K2A   = %016llx\n", (unsigned long long)K2A);
    fflush(stdout);
  }

  printf ("Generate phase 2 data...");
  fflush(stdout);
  // Generate structure of nonces
#pragma omp parallel for private(C) private(clen) firstprivate(N)
  for (unsigned n=0; n<DATA*SQRT2; n++) {
    uint64_t S = _pdep_u64(n, 0xf0f0f0f0f0f0f0f0LL);
    uint8_t M[BLOCKSIZE] = {n, 0, 0, 0, n};
    for (int i=0; i<5; i++) {
      S = inverse_round_function(S);
    }
    S ^= K2A;
    uint8_t N[BLOCKSIZE];
    for (int i=0; i<BLOCKSIZE; i++) {
      N[i] = S>>(56-8*i);
    }
    crypto_aead_encrypt((uint8_t*)C, &clen, M, sizeof(M), NULL, 0, NULL, N, flexAEAD);
    assert(clen <= sizeof(C));
    data[n] = (data_t){C: C[1], N: n, t: 0};
  }
  printf ("Done\n");
  fflush(stdout);
  
  // Look for collisions
  // qsort(data, 2*DATA, sizeof(data_t), compare_data);
  sort_data(data, DATA*SQRT2);
  n=0;
  for (unsigned i=1; i<DATA*SQRT2; i++)
    if (data[i].C == data[i-1].C)  n++;
  printf ("Found %i collisions\n", n);
  fflush(stdout);
  
  for (unsigned i=1; i<DATA*SQRT2; i++) {
    if (data[i].C == data[i-1].C) {
      /* for (int z=0; z<2; z++) { */
      /* 	uint64_t S = _pdep_u64(data[i-z].N, 0xf0f0f0f0f0f0f0f0LL); */
      /* 	uint8_t M[BLOCKSIZE] = {data[i-z].N}; */
      /* 	for (int i=0; i<5; i++) { */
      /* 	  S = inverse_round_function(S); */
      /* 	} */
      /* 	S ^= K2A; */
      /* 	uint8_t N[BLOCKSIZE]; */
      /* 	for (int i=0; i<BLOCKSIZE; i++) { */
      /* 	  N[i] = S>>(56-8*i); */
      /* 	} */
      /* 	flexAEAD_dbg = 1; */
      /* 	crypto_aead_encrypt((uint8_t*)C, &clen, M, sizeof(M), NULL, 0, NULL, N, flexAEAD); */
      /* 	flexAEAD_dbg = 0; */
      /* } */

      uint64_t S0 = _pdep_u64(data[i-1].N, 0xf0f0f0f0f0f0f0f0LL);
      uint64_t S1 = _pdep_u64(data[i  ].N, 0xf0f0f0f0f0f0f0f0LL);

      int filter_diff(uint64_t delta) {
	if ((delta & 0x00ffffff00ffffffLL) == 0) {
	  uint64_t d = _pext_u64(S0^S1, 0xf0f0);
	  d = (d<<56) | (d<<24);
	  if (delta == d)
	    return 1;
	}
	return 0;
      }
      int test_state(uint64_t S) {
	return test_K2B3A(S^S0, S0, S1);
      }
      
      if (recover_state(S0, S1, filter_diff, test_state))
	break;
    }
  } 

  if (!K2B3A) {
    printf ("Failed to recover K2B3A\n");
    exit(0);
  } else {
    printf ("Recovered K2B3A = %016llx\n", (unsigned long long)K2B3A);
    fflush(stdout);
  }

  // X0,Y0
  free(data);
  {
    // Allocate with mmap using scratch file
    int fd;
    fd = open(DIR "/mmap.tmp", O_RDWR | O_CREAT | O_TRUNC, 0644);
    // fd = open(DIR "/mmap.tmp", O_RDWR, 0644);
    if (!fd) {
      perror("open failed");
      exit(-1);
    }
#if 0
    int err = ftruncate(fd, sizeof(data_t)*DATA2);
    if (err) {
      perror("ftruncate failed");
      exit(-1);
    }    
#else
#define BUFSIZE (1ULL<<30)
    void *scratch = calloc(BUFSIZE, 1);
    for (unsigned i=0; i<sizeof(data_t)*(DATA2+BUFSIZE-1)/BUFSIZE; i++) {
      int r = write(fd, scratch, BUFSIZE);
      if (r != BUFSIZE) {
	perror("mmap failed");
	exit(-1);
      }
    }
    free(scratch);
#endif
    data = mmap(NULL, sizeof(data_t)*DATA2, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (!data) {
      perror("mmap failed");
      exit(-1);
    }
    madvise(data, sizeof(data_t)*DATA2, MADV_SEQUENTIAL);
  }
  
  printf ("Generate phase 3 data...");
  fflush(stdout);

  // Identify nonce with no carries
  uint64_t X0 = 0;
  {
    uint64_t C0[TAGSIZE/8];
    unsigned long long clen;
    uint8_t N[BLOCKSIZE] = {42};
    uint8_t M[0];

    crypto_aead_encrypt((uint8_t*)C0, &clen, M, sizeof(M), NULL, 0, NULL, N, flexAEAD);

    for (int n=0; n<64; n++) {
      uint64_t X;
      int r = getrandom(&X, sizeof(X), 0);
      assert(r == sizeof(X));

      uint64_t S = X;
      for (int i=0; i<5; i++)
	S = inverse_round_function(S);
      S ^= K2A;
      uint8_t N[BLOCKSIZE];
      for (int i=0; i<BLOCKSIZE; i++) {
	N[i] = S>>(56-8*i);
      }

      uint8_t M[2*BLOCKSIZE] = {0};
      S = X^K2B3A^0x0100000001000000LL;
      for (int i=0; i<5; i++)
	S = round_function(S);
      for (int i=0; i<BLOCKSIZE; i++) {
	M[i] = S>>(56-8*i);
      }
      S = X^K2B3A^0x0200000002000000LL;
      for (int i=0; i<5; i++)
	S = round_function(S);
      for (int i=0; i<BLOCKSIZE; i++) {
	M[BLOCKSIZE+i] = S>>(56-8*i);
      }
      
      uint64_t C[TAGSIZE/8];
      crypto_aead_encrypt((uint8_t*)C, &clen, NULL, 0, M, sizeof(M), NULL, N, flexAEAD);
      assert(clen <= sizeof(C));
      
      if (C0[0] == C[0]) {
	X0 = X;
	break;
      }
    }
  }
  if (!X0) {
    printf ("Failed to locate carry-less nonce\n");
    exit(0);
  }
  
  // Generate structure of Si
#pragma omp parallel for private(C) private(clen) firstprivate(N)
  for (uint64_t n=0; n<DATA2; n++) {
    uint64_t delta = _pdep_u64(n, 0x00ffffff00ffffffLL);
    // Build (N,S) pairs without touching carries
    uint64_t S = X0^delta;
    for (int i=0; i<5; i++)
      S = inverse_round_function(S);
    S ^= K2A;
    uint8_t N[BLOCKSIZE];
    for (int i=0; i<BLOCKSIZE; i++) {
      N[i] = S>>(56-8*i);
    }

    uint8_t M[2*BLOCKSIZE] = {0};
    S = X0^delta^K2B3A^0x0100000001000000LL;
    for (int i=0; i<5; i++)
      S = round_function(S);
    S ^= 0xdeadbeefLL*n;
    for (int i=0; i<BLOCKSIZE; i++) {
      M[i] = S>>(56-8*i);
    }
    S = X0^delta^K2B3A^0x0200000002000000LL;
    for (int i=0; i<5; i++)
      S = round_function(S);
    S ^= 0xdeadbeefLL*n;
    S ^= 0xf0000000f0000000LL;
    for (int i=0; i<BLOCKSIZE; i++) {
      M[BLOCKSIZE+i] = S>>(56-8*i);
    }

    crypto_aead_encrypt((uint8_t*)C, &clen, NULL, 0, M, sizeof(M), NULL, N, flexAEAD);
    assert(clen <= sizeof(C));
    data[n] = (data_t){C: __builtin_bswap64(C[0]), N: n, t: 0};
  }
  printf ("Done\n");
  fflush(stdout);

  // Look for collisions
  // qsort(data, DATA2, sizeof(data_t), compare_data);
  time_t now;
  time(&now);
  printf("Starting sort at: %s\n", ctime(&now));
  fflush(stdout);
  sort_data_large(data, DATA2);
  time(&now);
  printf("Finished sort at: %s\n", ctime(&now));
  fflush(stdout);

  unsigned n_coll=0;
  for (uint64_t i=1; i<DATA2; i++)
    if (data[i].C == data[i-1].C)  n_coll++;
  printf ("Found %i collisions\n", n_coll);
  fflush(stdout);

  data_t *coll = malloc(2*n_coll*sizeof(data_t));
  n_coll = 0;
  for (uint64_t i=1; i<DATA2; i++) {
    if (data[i].C == data[i-1].C) {
      coll[2*n_coll  ] = data[i-1];
      coll[2*n_coll+1] = data[i];
      n_coll++;
    }
  }
  
  {
    int filter_diff(uint64_t delta) {
      return 1;
    }

    int test_state(uint64_t X) {
      // Try all collisions
      for (unsigned i=0; i<n_coll; i++) {
	
	uint64_t S0 =  0xdeadbeefLL*coll[2*i].N;
	uint64_t S1 = (0xdeadbeefLL*coll[2*i].N) ^ 0xf0000000f0000000LL;

	uint64_t T0 =  0xdeadbeefLL*coll[2*i+1].N;
	uint64_t T1 = (0xdeadbeefLL*coll[2*i+1].N) ^ 0xf0000000f0000000LL;

	uint64_t K = S0 ^ X;

	S0 ^= K;
	S1 ^= K;
	T0 ^= K;
	T1 ^= K;

	for (int i=0; i<5; i++) {
	  S0 = round_function(S0);
	  S1 = round_function(S1);
	  T0 = round_function(T0);
	  T1 = round_function(T1);
	}

	if ((S0^S1) == (T0^T1)) {
	  K2A3B = K;
	  printf ("K2A3B candidate: %016llx\n", (unsigned long long)K2A3B);
	  fflush(stdout);
	  // return 1;
	}
      }

      return 0;
    }

    recover_state(0, 0xf0000000f0000000LL, filter_diff, test_state);
  }
    
  if (!K2A3B) {
    printf ("Failed to recover K2A3B\n");
    exit(0);
  }  
}

uint64_t round_function(uint64_t x) {
  uint64_t T = _pdep_u64(x>>32, 0xf0f0f0f0f0f0f0f0) | _pdep_u64(x, 0x0f0f0f0f0f0f0f0f);
  uint32_t R = T;
  uint32_t L = T>>32;
  R = SBOX(R);
  L ^= R;
  L = SBOX(L);
  R ^= L;
  R = SBOX(R);
  return R | ((uint64_t)L)<<32;
}

uint64_t inverse_round_function(uint64_t x) {
  uint32_t R = x;
  uint32_t L = x>>32;
  R = SBOXI(R);
  R ^= L;
  L = SBOXI(L);
  L ^= R;
  R = SBOXI(R);
  uint64_t T = R | ((uint64_t)L)<<32;
  return _pext_u64(T,0x0f0f0f0f0f0f0f0f) | _pext_u64(T,0xf0f0f0f0f0f0f0f0)<<32;
}

int filter_diff_phase1(uint64_t delta) {
  return ( ((delta & 0x00ffffff00ffffffLL) == 0) &&
	   ((delta & 0x0100000001000000LL) == 0x0100000001000000LL) &&
	   __builtin_popcountll((delta>>24) + 0x0100000001) == 2);
}

int test_K2A (uint64_t K) {
  for (int n=0; n<2; n++) {
    // Build pair that should collide
    uint64_t S0 = 0x0000000000000000LL ^ (n<<24);
    uint64_t S1 = 0x0100000001000000LL ^ (n<<24);
    for (int i=0; i<5; i++) {
      S0 = inverse_round_function(S0);
      S1 = inverse_round_function(S1);
    }
    S0 ^= K;
    S1 ^= K;
    uint8_t N0[BLOCKSIZE];
    uint8_t N1[BLOCKSIZE];
    for (int i=0; i<BLOCKSIZE; i++) {
      N0[i] = S0>>(56-8*i);
      N1[i] = S1>>(56-8*i);
    }
    uint8_t M[2*BLOCKSIZE] = {0};
    uint64_t C0[(2*BLOCKSIZE+TAGSIZE)/8];
    uint64_t C1[(2*BLOCKSIZE+TAGSIZE)/8];
    unsigned long long clen;
    crypto_aead_encrypt((uint8_t*)C0, &clen, M, sizeof(M), NULL, 0, NULL, N0, flexAEAD);
    assert(clen <= sizeof(C0));
    crypto_aead_encrypt((uint8_t*)C1, &clen, M, sizeof(M), NULL, 0, NULL, N1, flexAEAD);
    assert(clen <= sizeof(C1));
  
    if (C0[0] == C1[1] || C0[1] == C1[0]) {
      K2A = K;
      return 1;
    }
  }

  return 0;
}

int test_pair_K2B3A (uint64_t X0, uint64_t X1, uint64_t Y0, uint64_t Y1) {
  // Build pair that should collide

  uint64_t S0 = X1;
  uint64_t S1 = X0;

  for (int i=0; i<5; i++) {
    S0 = inverse_round_function(S0);
    S1 = inverse_round_function(S1);
  }
  S0 ^= K2A;
  S1 ^= K2A;
  uint8_t N0[BLOCKSIZE];
  uint8_t N1[BLOCKSIZE];
  for (int i=0; i<BLOCKSIZE; i++) {
    N0[i] = S0>>(56-8*i);
    N1[i] = S1>>(56-8*i);
  }
  
  S0 = Y0;
  S1 = Y1;
  for (int i=0; i<5; i++) {
    S0 = round_function(S0);
    S1 = round_function(S1);
  }
  uint8_t M0[BLOCKSIZE];
  uint8_t M1[BLOCKSIZE];
  for (int i=0; i<BLOCKSIZE; i++) {
    M0[i] = S0>>(56-8*i);
    M1[i] = S1>>(56-8*i);
  }

  uint64_t C0[(BLOCKSIZE+TAGSIZE)/8];
  uint64_t C1[(BLOCKSIZE+TAGSIZE)/8];
  unsigned long long clen;
  crypto_aead_encrypt((uint8_t*)C0, &clen, M0, sizeof(M0), NULL, 0, NULL, N0, flexAEAD);
  assert(clen <= sizeof(C0));
  crypto_aead_encrypt((uint8_t*)C1, &clen, M1, sizeof(M1), NULL, 0, NULL, N1, flexAEAD);
  assert(clen <= sizeof(C1));
  
  if (C0[1] == C1[1]) {
    // printf ("## %08x %08x\n", C0[1], C1[1]);
    return 1;
  }

  return 0;
}

int test_K2B3A (uint64_t K, uint64_t X0, uint64_t X1) {
  static int n = 0;
  n++;
  uint64_t KD = 0;
  uint64_t d = 0x0012345600789abcLL;
  if (test_pair_K2B3A(X0, X1^d, X0^K, X1^K^d)) {
    /* printf ("Candidate key: %016llx\n", K); */

    // Clean up carries from plus-one
    if (test_pair_K2B3A(X0, X0^(2ULL<<24), X0^K, X0^K^(2ULL<<24))) {
      // Ok, no carry
      KD ^= 1ULL<<24;
    } else {
      for (uint64_t mask=3; mask<0x100; mask=2*mask+1) {
    	if (test_pair_K2B3A(X0, X0^(1ULL<<24), X0^K, X0^K^(mask<<24))) {
    	  KD ^= mask<<24;
    	  break;
    	}
      }
    }
    if (test_pair_K2B3A(X0, X0^(2ULL<<56), X0^K, X0^K^(2ULL<<56))) {
      // Ok, no carry
      KD ^= 1ULL<<56;
    } else {
      for (uint64_t mask=3; mask<0x100; mask=2*mask+1) {
    	if (test_pair_K2B3A(X0, X0^(1ULL<<56), X0^K, X0^K^(mask<<56))) {
    	  KD ^= mask<<56;
    	  break;
    	}
      }
    }
    if ((KD&0xff00000000000000LL) == 0 || (KD&0x00000000ff000000LL) == 0) {
      return 0;
    }
    K2B3A = K^KD;
    /* printf ("Cleaned-up   : %016llx [n=%i]\n", (unsigned long long)(K^KD), n); */
    return 1;
  } else {
    return 0;
  }
}

// Recover internal state from difference,
// assuming differential path is followed
// Callbacks:
// - filter_diff to test output difference
// - test_state is called on each candidate
uint64_t recover_state (uint64_t S0, uint64_t S1, callback_t filter_diff, callback_t test_state) {
  printf("Trying to recover key from pair (%016llx %016llx)\n", (unsigned long long)S0, (unsigned long long)S1);
  int ret = 0;
  // first superbox
#pragma omp parallel for schedule(dynamic)
  for (uint32_t k1=0; k1 < 0x10000; k1++) {
    uint64_t T0 = S0;
    uint64_t T1 = S1;
    T0 ^= _pdep_u64(k1, 0xf000f000f000f000LL);
    T1 ^= _pdep_u64(k1, 0xf000f000f000f000LL);
    T0 = round_function(T0);
    T1 = round_function(T1);

    if ( (((T0^T1) & 0x0f0000000f000000LL) == 0) ||
	 (((T0^T1) & 0xf0000000f0000000LL) == 0) ) {

      // second superbox
      for (uint32_t k2=0; k2 < 0x10000; k2++) {
	T0 = S0;
	T1 = S1;
	T0 ^= _pdep_u64(k1, 0xf000f000f000f000LL);
	T1 ^= _pdep_u64(k1, 0xf000f000f000f000LL);
	T0 ^= _pdep_u64(k2, 0x00f000f000f000f0LL);
	T1 ^= _pdep_u64(k2, 0x00f000f000f000f0LL);
	T0 = round_function(T0);
	T1 = round_function(T1);
      
	if ( (((T0^T1) & 0x0fff0fff0fff0fffLL) == 0) ||
	     (((T0^T1) & 0xf0fff0fff0fff0ffLL) == 0) ) {
	  T0 = round_function(T0);
	  T1 = round_function(T1);

	  uint64_t mask = 0;
	  
	  if ( (((T0^T1) & 0x0fffffff0fffffffLL) == 0) ||
	       (((T0^T1) & 0xff0fffffff0fffffLL) == 0) )
	    mask = 0xffff0f0fffff0f0fLL;
	  if ( (((T0^T1) & 0xf0fffffff0ffffffLL) == 0) ||
	       (((T0^T1) & 0xfff0fffffff0ffffLL) == 0) )
	    mask = 0xfffff0f0fffff0f0LL;
	    
	  if (mask) {
	    int n = 0;
	    // printf ("### %04x %04x\n", k1, k2);
	    
	    // Guess additional bytes
	    for (uint32_t Y=0; Y<0x10000; Y++) {
	      uint64_t U0 = T0 & mask;
	      uint64_t U1 = T1 & mask;
	      U0 |= _pdep_u64(Y, ~mask);
	      U1 |= _pdep_u64(Y, ~mask);
	      U0 = round_function(U0);
	      U1 = round_function(U1);
	      U0 = round_function(U0);
	      U1 = round_function(U1);
	      if ( (((U0^U1) & 0x0fffffff0fffffffLL) == 0) ||
		   (((U0^U1) & 0xffff0fffffff0fffLL) == 0) ) {
		// Guess final bytes
		for (uint32_t Z=0; Z<0x10000; Z++) {
		  n++;
		  U0 = T0 & 0xffff0000ffff0000LL;
		  U1 = T1 & 0xffff0000ffff0000LL;
		  U0 |= _pdep_u64(Y, ~mask);
		  U1 |= _pdep_u64(Y, ~mask);
		  U0 |= _pdep_u64(Z, (~mask)^0x0000ffff0000ffffLL);
		  U1 |= _pdep_u64(Z, (~mask)^0x0000ffff0000ffffLL);
		  U0 = round_function(U0);
		  U1 = round_function(U1);
		  U0 = round_function(U0);
		  U1 = round_function(U1);
		  U0 = round_function(U0);
		  U1 = round_function(U1);
		  uint64_t delta = U0^U1;
		  if (filter_diff(delta)) {
		    U0 = inverse_round_function(U0);
		    U1 = inverse_round_function(U1);
		    U0 = inverse_round_function(U0);
		    U1 = inverse_round_function(U1);
		    U0 = inverse_round_function(U0);
		    U1 = inverse_round_function(U1);
		    U0 = inverse_round_function(U0);
		    U1 = inverse_round_function(U1);
		    U0 = inverse_round_function(U0);
		    U1 = inverse_round_function(U1);
		    assert((S0^U0) == (S1^U1));
		    /* printf ("Candidate key: %016llx [delta:%016llx] [%04x %04x]\n", */
		    /* 	    (unsigned long long)(S0^U0), (unsigned long long)delta, k1, k2); */
		    if (test_state(U0)) {
		      // printf ("Recovered key? %016llx [delta:%016llx]\n", (unsigned long long)(S0^U0), (unsigned long long)delta);
		      #pragma omp critical
		      {
			ret=1;
		      }
		    }
		  }
		}
	      }
	    }
	  }
	}
      }
    }
  }

  return ret;
}


void print_diff_state (uint8_t S0[BLOCKSIZE], uint8_t S1[BLOCKSIZE]) {
  for (int i=0; i<BLOCKSIZE; i++)
    printf(" %01x%01x", (S0[i]^S1[i])&0xf, (S0[i]^S1[i])>>4);
  printf ("\n");
}

inline void dirShuffleLayer( unsigned char * block, unsigned long long blocklen, unsigned char * state )
{
	unsigned long long i = 0;
	for( i=0; i<blocklen/2; i++)
	{
		*(state+2*i+0) = ( (*(block+i+0)) & 0xf0)    + ((*(block+i+(blocklen/2))&0xf0)>>4);
		*(state+2*i+1) = ( (*(block+i+0)  & 0x0f)<<4)  + ((*(block+i+(blocklen/2))&0x0f)); 
	}
	memcpy( block, state, blocklen);
	return;
}

/* void print_diff_pair (data_t a, data_t b) { */
/*   uint8_t N0[BLOCKSIZE] = {0}; */
/*   uint8_t N1[BLOCKSIZE] = {0}; */
/*   uint8_t M[2*BLOCKSIZE] = {0}; */
/*   uint64_t C[(2*BLOCKSIZE+TAGSIZE)/8]; */
/*   unsigned long long clen; */
  
/*   make_nonce(N0, a.N); */
/*   make_nonce(N1, b.N); */
/*   flexAEAD_dbg = 1; */
/*   crypto_aead_encrypt((uint8_t*)C, &clen, M, sizeof(M), NULL, 0, NULL, N0, flexAEAD); */
/*     crypto_aead_encrypt((uint8_t*)C, &clen, M, sizeof(M), NULL, 0, NULL, N1, flexAEAD); */
/*   flexAEAD_dbg = 0; */
/* } */
