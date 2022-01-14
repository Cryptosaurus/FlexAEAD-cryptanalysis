CFLAGS   = -Wall -Wextra -g -O3 -fopenmp -march=native
CXXFLAGS = $(CFLAGS)
LD_LIBS  = -lstxxl

key_recovery: encrypt.o parallel_sort.o key_recovery.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LD_LIBS)
