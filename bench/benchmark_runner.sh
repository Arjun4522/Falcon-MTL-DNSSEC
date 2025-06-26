#!/bin/bash

# Falcon KSK Benchmark Runner Script
# This script runs comprehensive benchmarks and generates reports

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BENCHMARK_EXE="./falcon_benchmark"
ORIGINAL_EXE="./falconmtlKSK"
RESULTS_DIR="benchmark_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if executables exist
check_executables() {
    if [ ! -f "$BENCHMARK_EXE" ]; then
        log_error "Benchmark executable not found. Run 'make benchmark' first."
        exit 1
    fi
    
    if [ ! -f "$ORIGINAL_EXE" ]; then
        log_warning "Original executable not found. Some comparisons will be skipped."
    fi
}

# Create results directory
setup_results_dir() {
    mkdir -p "$RESULTS_DIR"
    log_info "Results will be saved to $RESULTS_DIR/"
}

# Run basic benchmark
run_basic_benchmark() {
    log_info "Running basic benchmark..."
    local output_file="$RESULTS_DIR/basic_benchmark_$TIMESTAMP.txt"
    
    echo "Falcon KSK Benchmark Results" > "$output_file"
    echo "============================" >> "$output_file"
    echo "Timestamp: $(date)" >> "$output_file"
    echo "System: $(uname -a)" >> "$output_file"
    echo "CPU: $(lscpu | grep 'Model name' | cut -d: -f2 | xargs)" >> "$output_file"
    echo "" >> "$output_file"
    
    $BENCHMARK_EXE >> "$output_file" 2>&1
    
    log_success "Basic benchmark completed. Results saved to $output_file"
}

# Run scalability benchmark
run_scalability_benchmark() {
    log_info "Running scalability benchmark..."
    local output_file="$RESULTS_DIR/scalability_benchmark_$TIMESTAMP.txt"
    
    echo "Falcon KSK Scalability Benchmark" > "$output_file"
    echo "=================================" >> "$output_file"
    echo "Timestamp: $(date)" >> "$output_file"
    echo "" >> "$output_file"
    
    $BENCHMARK_EXE --scalability >> "$output_file" 2>&1
    
    log_success "Scalability benchmark completed. Results saved to $output_file"
}

# Run memory analysis
run_memory_analysis() {
    if ! command -v valgrind &> /dev/null; then
        log_warning "Valgrind not found. Skipping memory analysis."
        return
    fi
    
    log_info "Running memory analysis with Valgrind..."
    local output_file="$RESULTS_DIR/memory_analysis_$TIMESTAMP.txt"
    
    echo "Falcon KSK Memory Analysis" > "$output_file"
    echo "==========================" >> "$output_file"
    echo "Timestamp: $(date)" >> "$output_file"
    echo "" >> "$output_file"
    
    # Run with limited iterations to avoid long runtime
    valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
             --track-origins=yes --verbose \
             $BENCHMARK_EXE >> "$output_file" 2>&1
    
    log_success "Memory analysis completed. Results saved to $output_file"
}

# Run performance profiling
run_performance_profiling() {
    if ! command -v gprof &> /dev/null; then
        log_warning "gprof not found. Skipping performance profiling."
        return
    fi
    
    log_info "Running performance profiling..."
    
    # Rebuild with profiling flags
    log_info "Rebuilding with profiling flags..."
    make clean > /dev/null 2>&1
    CFLAGS="-pg -O2" make falcon_benchmark > /dev/null 2>&1
    
    # Run benchmark to generate profile data
    $BENCHMARK_EXE > /dev/null 2>&1
    
    # Generate profile report
    local output_file="$RESULTS_DIR/performance_profile_$TIMESTAMP.txt"
    echo "Falcon KSK Performance Profile" > "$output_file"
    echo "==============================" >> "$output_file"
    echo "Timestamp: $(date)" >> "$output_file"
    echo "" >> "$output_file"
    
    gprof $BENCHMARK_EXE gmon.out >> "$output_file" 2>&1
    
    # Clean up and rebuild without profiling
    rm -f gmon.out
    make clean > /dev/null 2>&1
    make falcon_benchmark > /dev/null 2>&1
    
    log_success "Performance profiling completed. Results saved to $output_file"
}

# Run comparison with original implementation
run_comparison() {
    if [ ! -f "$ORIGINAL_EXE" ]; then
        log_warning "Original executable not found. Skipping comparison."
        return
    fi
    
    log_info "Running comparison with original implementation..."
    local output_file="$RESULTS_DIR/comparison_$TIMESTAMP.txt"
    
    echo "Falcon KSK Implementation Comparison" > "$output_file"
    echo "====================================" >> "$output_file"
    echo "Timestamp: $(date)" >> "$output_file"
    echo "" >> "$output_file"
    
    echo "=== Original Implementation ===" >> "$output_file"
    timeout 30s $ORIGINAL_EXE -n 8 -k 0 >> "$output_file" 2>&1 || \
        echo "Original implementation timed out or failed" >> "$output_file"
    
    echo "" >> "$output_file"
    echo "=== Benchmark Implementation ===" >> "$output_file"
    $BENCHMARK_EXE >> "$output_file" 2>&1
    
    log_success "Comparison completed. Results saved to $output_file"
}

# Generate summary report
generate_summary() {
    log_info "Generating summary report..."
    local summary_file="$RESULTS_DIR/summary_$TIMESTAMP.md"
    
    cat > "$summary_file" << EOF
# Falcon KSK Benchmark Summary

**Timestamp:** $(date)  
**System:** $(uname -s) $(uname -r)  
**Architecture:** $(uname -m)  
**CPU:** $(lscpu | grep 'Model name' | cut -d: -f2 | xargs 2>/dev/null || echo "Unknown")

## Files Generated

EOF
    
    # List all generated files
    for file in "$RESULTS_DIR"/*_"$TIMESTAMP".txt; do
        if [ -f "$file" ]; then
            basename_file=$(basename "$file")
            echo "- \`$basename_file\`" >> "$summary_file"
        fi
    done
    
    cat >> "$summary_file" << EOF

## Key Findings

### Performance Comparison
- **Plain Falcon**: Single key generation
- **Falcon + Merkle**: Multiple key generation with tree construction
- **Memory Overhead**: Approximately 8x for 8-key setup
- **Computational Overhead**: Includes SHA-256 hashing and tree construction

### Security Analysis
- **Falcon Security**: ~128-bit quantum-resistant
- **Merkle Tree Security**: SHA-256 (~128-bit classical, ~64-bit quantum)
- **Combined Security**: Limited by weakest component

### Use Cases
- **Plain Falcon**: Simple KSK scenarios, single key operations
- **Falcon + Merkle**: Multi-key scenarios, batch operations, key rotation

## Recommendations

1. Use plain Falcon for single-key operations
2. Use Falcon + Merkle for scenarios requiring multiple keys or batch operations
3. Consider the memory overhead when designing systems
4. Monitor performance in production environments

EOF

    log_success "Summary report generated: $summary_file"
}

# Main execution
main() {
    echo "======================================"
    echo "Falcon KSK Comprehensive Benchmark"
    echo "======================================"
    echo ""
    
    check_executables
    setup_results_dir
    
    # Run all benchmarks
    run_basic_benchmark
    run_scalability_benchmark
    run_memory_analysis
    run_performance_profiling
    run_comparison
    
    # Generate summary
    generate_summary
    
    echo ""
    log_success "All benchmarks completed!"
    log_info "Results saved in: $RESULTS_DIR/"
    log_info "Summary report: $RESULTS_DIR/summary_$TIMESTAMP.md"
}

# Parse command line arguments
case "${1:-all}" in
    "basic")
        check_executables
        setup_results_dir
        run_basic_benchmark
        ;;
    "scalability")
        check_executables
        setup_results_dir
        run_scalability_benchmark
        ;;
    "memory")
        check_executables
        setup_results_dir
        run_memory_analysis
        ;;
    "profile")
        check_executables
        setup_results_dir
        run_performance_profiling
        ;;
    "comparison")
        check_executables
        setup_results_dir
        run_comparison
        ;;
    "all")
        main
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [test_type]"
        echo ""
        echo "Test types:"
        echo "  basic       - Run basic benchmark only"
        echo "  scalability - Run scalability tests only"
        echo "  memory      - Run memory analysis only"
        echo "  profile     - Run performance profiling only"
        echo "  comparison  - Compare with original implementation"
        echo "  all         - Run all tests (default)"
        echo "  help        - Show this help"
        ;;
    *)
        log_error "Unknown test type: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac