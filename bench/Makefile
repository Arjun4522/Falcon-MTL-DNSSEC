# Makefile for Falcon KSK Benchmark

CC = gcc
CFLAGS = -Wall -Wextra -O3 -march=native -mtune=native
LIBS = -lssl -lcrypto -lm
FALCON_LIB = ./libfalcon.a  # Adjust this based on your Falcon library setup

# Source files
BENCHMARK_SRC = falcon_benchmark.c
ORIGINAL_SRC = falconmtlKSK.c

# Object files
BENCHMARK_OBJ = $(BENCHMARK_SRC:.c=.o)
ORIGINAL_OBJ = $(ORIGINAL_SRC:.c=.o)

# Executables
BENCHMARK_EXE = falcon_benchmark
ORIGINAL_EXE = falconmtlKSK

# Default target
all: $(BENCHMARK_EXE) $(ORIGINAL_EXE)

# Benchmark executable
$(BENCHMARK_EXE): $(BENCHMARK_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(FALCON_LIB)

# Original executable
$(ORIGINAL_EXE): $(ORIGINAL_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(FALCON_LIB)

# Object files
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Run benchmark
benchmark: $(BENCHMARK_EXE)
	@echo "Running comprehensive benchmark..."
	./$(BENCHMARK_EXE)

# Run benchmark with scalability test
benchmark-full: $(BENCHMARK_EXE)
	@echo "Running full benchmark with scalability tests..."
	./$(BENCHMARK_EXE) --scalability

# Run original implementation for comparison
test-original: $(ORIGINAL_EXE)
	@echo "Running original implementation..."
	./$(ORIGINAL_EXE) -n 8 -k 0

# Performance profiling with gprof
profile: CFLAGS += -pg
profile: $(BENCHMARK_EXE)
	./$(BENCHMARK_EXE)
	gprof $(BENCHMARK_EXE) gmon.out > profile_report.txt
	@echo "Profile report saved to profile_report.txt"

# Memory analysis with valgrind
memcheck: $(BENCHMARK_EXE)
	valgrind --tool=memcheck --leak-check=full --track-origins=yes ./$(BENCHMARK_EXE)

# Performance analysis with perf (Linux only)
perf-analysis: $(BENCHMARK_EXE)
	perf record -g ./$(BENCHMARK_EXE)
	perf report

# Clean build artifacts
clean:
	rm -f $(BENCHMARK_OBJ) $(ORIGINAL_OBJ) $(BENCHMARK_EXE) $(ORIGINAL_EXE)
	rm -f gmon.out profile_report.txt perf.data*

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y libssl-dev build-essential valgrind linux-tools-generic

# Help
help:
	@echo "Available targets:"
	@echo "  all           - Build both benchmark and original executables"
	@echo "  benchmark     - Run comprehensive benchmark"
	@echo "  benchmark-full- Run benchmark with scalability tests"
	@echo "  test-original - Run original implementation"
	@echo "  profile       - Run with gprof profiling"
	@echo "  memcheck      - Run with valgrind memory analysis"
	@echo "  perf-analysis - Run with perf profiling (Linux only)"
	@echo "  clean         - Clean build artifacts"
	@echo "  install-deps  - Install dependencies (Ubuntu/Debian)"
	@echo "  help          - Show this help"

.PHONY: all benchmark benchmark-full test-original profile memcheck perf-analysis clean install-deps help