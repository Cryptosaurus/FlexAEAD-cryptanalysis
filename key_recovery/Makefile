CFLAGS= -Wall -Wextra -g -O3 -fopenmp -march=native
CXXFLAGS = $(CFLAGS)

key_recovery: encrypt.o parallel_sort.o key_recovery.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LD_LIBS)
