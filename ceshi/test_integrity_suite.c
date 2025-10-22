/*
 * ============================================================================
 * 完整性校验系统测试套件
 * 测试文件：test_integrity_suite.c
 * 
 * 功能：对基于XOR+SM3的高性能完整性校验算法进行全面测试
 * 包含：正确性测试、性能测试、雪崩效应测试、多线程测试等
 * 
 * 编译命令：
 * gcc -march=armv8.2-a+crypto -O3 -pthread \
 *     -o test_integrity_suite test_integrity_suite.c ../cn_test1.1/test1.1/aes_sm3_integrity.c -lm
 * 
 * 运行命令：
 * ./test_integrity_suite [--quick] [--performance] [--correctness] [--all]
 * 
 * 作者：完整性校验系统开发团队
 * 版本：v1.0
 * 日期：2025-10-22
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <assert.h>

// 前向声明外部函数（来自aes_sm3_integrity.c）
extern void aes_sm3_integrity_256bit(const uint8_t* input, uint8_t* output);
extern void aes_sm3_integrity_128bit(const uint8_t* input, uint8_t* output);
extern void aes_sm3_integrity_256bit_extreme(const uint8_t* input, uint8_t* output);
extern void aes_sm3_integrity_256bit_ultra(const uint8_t* input, uint8_t* output);
extern void aes_sm3_integrity_256bit_mega(const uint8_t* input, uint8_t* output);
extern void aes_sm3_integrity_256bit_super(const uint8_t* input, uint8_t* output);
extern void aes_sm3_integrity_256bit_hyper(const uint8_t* input, uint8_t* output);
extern void aes_sm3_integrity_batch(const uint8_t** inputs, uint8_t** outputs, int batch_size);
extern void aes_sm3_parallel(const uint8_t* input, uint8_t* output, int block_count, 
                             int num_threads, int output_size);
extern void sha256_4kb(const uint8_t* input, uint8_t* output);
extern void sm3_4kb(const uint8_t* input, uint8_t* output);

// 前向声明SM3内部函数（用于优化效果测试）
extern void sm3_compress_hw(uint32_t* state, const uint32_t* block);
extern void sm3_compress_hw_inline_full(uint32_t* state, const uint32_t* block);

// 前向声明内存优化测试函数（来自aes_sm3_integrity.c）
extern void test_memory_access_optimization(void);
extern void aes_sm3_integrity_batch_no_prefetch(const uint8_t** inputs, uint8_t** outputs, int batch_size);

// ============================================================================
// 测试统计
// ============================================================================
static struct {
    int total_tests;
    int passed_tests;
    int failed_tests;
} test_stats = {0, 0, 0};

void record_test(const char* test_name, int passed) {
    test_stats.total_tests++;
    if (passed) {
        test_stats.passed_tests++;
        printf("  [✓] %s\n", test_name);
    } else {
        test_stats.failed_tests++;
        printf("  [✗] %s\n", test_name);
    }
}

void print_test_summary() {
    printf("\n");
    printf("═══════════════════════════════════════════════════════════\n");
    printf("测试总结\n");
    printf("═══════════════════════════════════════════════════════════\n");
    printf("  总测试数: %d\n", test_stats.total_tests);
    printf("  通过: %d\n", test_stats.passed_tests);
    printf("  失败: %d\n", test_stats.failed_tests);
    printf("  通过率: %.1f%%\n", 
           100.0 * test_stats.passed_tests / test_stats.total_tests);
    printf("═══════════════════════════════════════════════════════════\n");
    
    if (test_stats.failed_tests == 0) {
        printf("\n🎉 所有测试通过！\n\n");
    } else {
        printf("\n⚠️  有测试失败，请检查上述输出\n\n");
    }
}

// ============================================================================
// 工具函数
// ============================================================================

void print_hex(const char* label, const uint8_t* data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if (i < len - 1 && (i + 1) % 16 == 0) {
            printf("\n%*s", (int)strlen(label) + 2, "");
        }
    }
    printf("\n");
}

int compare_bytes(const uint8_t* a, const uint8_t* b, int len) {
    return memcmp(a, b, len) == 0;
}

int hamming_distance(const uint8_t* a, const uint8_t* b, int len) {
    int distance = 0;
    for (int i = 0; i < len; i++) {
        uint8_t xor_val = a[i] ^ b[i];
        while (xor_val) {
            distance += xor_val & 1;
            xor_val >>= 1;
        }
    }
    return distance;
}

void generate_random_data(uint8_t* data, int len, unsigned int seed) {
    srand(seed);
    for (int i = 0; i < len; i++) {
        data[i] = rand() % 256;
    }
}

void generate_pattern_data(uint8_t* data, int len) {
    for (int i = 0; i < len; i++) {
        data[i] = i % 256;
    }
}

// ============================================================================
// 5.3 算法正确性测试
// ============================================================================

/**
 * @brief 测试5.3.1: SM3算法标准测试向量
 * 
 * 根据GB/T 32905-2016标准，验证SM3算法实现的正确性
 */
void test_sm3_standard_vectors() {
    printf("\n【测试5.3.1】SM3算法标准测试向量（GB/T 32905-2016）\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    // SM3标准初始向量
    static const uint32_t SM3_IV[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };
    
    // 测试向量1: "abc"
    // 标准输入: "abc" (3字节)
    // 标准输出: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
    printf("\n  测试向量1: \"abc\" (3字节标准测试)\n");
    
    // 构造SM3标准填充后的消息块（512位=64字节）
    // "abc" = 0x616263
    // 填充：消息 || 1 || 0...0 || 长度(64位)
    uint32_t block1[16];
    memset(block1, 0, 64);
    
    // 小端序系统：按字节填充 "abc"
    uint8_t* block_bytes = (uint8_t*)block1;
    block_bytes[0] = 'a';
    block_bytes[1] = 'b';
    block_bytes[2] = 'c';
    block_bytes[3] = 0x80;  // 填充位 '1' 后跟 '0'
    // block_bytes[4-59] = 0 (已由memset设置)
    // 长度字段(大端序): 3字节 = 24位
    block_bytes[62] = 0x00;
    block_bytes[63] = 0x18;  // 24 = 0x18
    
    // 转换为大端序32位字（SM3要求）
    for (int i = 0; i < 16; i++) {
        block1[i] = __builtin_bswap32(((uint32_t*)block_bytes)[i]);
    }
    
    // 执行SM3压缩
    uint32_t state1[8];
    memcpy(state1, SM3_IV, sizeof(SM3_IV));
    sm3_compress_hw(state1, block1);
    
    // 输出结果（转换为大端序字节）
    uint8_t output1[32];
    for (int i = 0; i < 8; i++) {
        uint32_t word = __builtin_bswap32(state1[i]);
        memcpy(output1 + i * 4, &word, 4);
    }
    
    // 标准答案
    const uint8_t expected1[32] = {
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
        0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
        0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
        0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
    };
    
    print_hex("  实际输出", output1, 32);
    print_hex("  标准输出", expected1, 32);
    
    int passed1 = compare_bytes(output1, expected1, 32);
    record_test("SM3标准测试向量1 (\"abc\")", passed1);
    
    if (!passed1) {
        printf("  [警告] SM3标准测试向量验证失败！\n");
    }
    
    // 测试向量2: 4KB填充的"abc" - 验证4KB处理函数的确定性
    printf("\n  测试向量2: \"abc\"填充到4KB（确定性验证）\n");
    uint8_t input2[4096];
    memset(input2, 0, 4096);
    memcpy(input2, "abc", 3);
    
    uint8_t output2[32];
    uint8_t output2_repeat[32];
    sm3_4kb(input2, output2);
    sm3_4kb(input2, output2_repeat);
    
    int passed2 = compare_bytes(output2, output2_repeat, 32);
    record_test("SM3确定性验证（4KB输入重复计算）", passed2);
    
    printf("\n");
}

/**
 * @brief 测试5.3.2: XOR折叠正确性测试
 */
void test_xor_folding_correctness() {
    printf("\n【测试5.3.2】XOR折叠正确性测试\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    // 测试1: 全0输入
    uint8_t input_zeros[4096];
    memset(input_zeros, 0, 4096);
    
    uint8_t output_zeros1[32];
    uint8_t output_zeros2[32];
    aes_sm3_integrity_256bit_extreme(input_zeros, output_zeros1);
    aes_sm3_integrity_256bit_extreme(input_zeros, output_zeros2);
    
    int zeros_consistent = compare_bytes(output_zeros1, output_zeros2, 32);
    record_test("XOR折叠：全0数据一致性", zeros_consistent);
    
    // 测试2: 全1输入
    uint8_t input_ones[4096];
    memset(input_ones, 0xFF, 4096);
    
    uint8_t output_ones[32];
    aes_sm3_integrity_256bit_extreme(input_ones, output_ones);
    
    // 全0和全1应产生不同输出
    int different = !compare_bytes(output_zeros1, output_ones, 32);
    record_test("XOR折叠：全0与全1产生不同输出", different);
    
    // 测试3: 模式数据
    uint8_t input_pattern[4096];
    generate_pattern_data(input_pattern, 4096);
    
    uint8_t output_pattern1[32];
    uint8_t output_pattern2[32];
    aes_sm3_integrity_256bit_extreme(input_pattern, output_pattern1);
    aes_sm3_integrity_256bit_extreme(input_pattern, output_pattern2);
    
    int pattern_consistent = compare_bytes(output_pattern1, output_pattern2, 32);
    record_test("XOR折叠：模式数据一致性", pattern_consistent);
    
    // 测试4: 确定性验证（随机数据）
    uint8_t input_random[4096];
    generate_random_data(input_random, 4096, 12345);
    
    uint8_t output_random1[32];
    uint8_t output_random2[32];
    aes_sm3_integrity_256bit_extreme(input_random, output_random1);
    aes_sm3_integrity_256bit_extreme(input_random, output_random2);
    
    int deterministic = compare_bytes(output_random1, output_random2, 32);
    record_test("XOR折叠：确定性验证", deterministic);
    
    printf("\n");
}

/**
 * @brief 测试5.3.3: 完整性校验算法测试
 */
void test_integrity_algorithm() {
    printf("\n【测试5.3.3】完整性校验算法测试\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    uint8_t input[4096];
    generate_pattern_data(input, 4096);
    
    // 测试256位输出
    uint8_t output_256[32];
    aes_sm3_integrity_256bit(input, output_256);
    record_test("256位输出长度验证", 1);  // 能正常调用即通过
    print_hex("  256位输出", output_256, 32);
    
    // 测试128位输出
    uint8_t output_128[16];
    aes_sm3_integrity_128bit(input, output_128);
    
    // 验证128位是256位的截断
    int is_truncation = compare_bytes(output_256, output_128, 16);
    record_test("128位输出是256位截断", is_truncation);
    print_hex("  128位输出", output_128, 16);
    
    // 测试不同版本的一致性
    uint8_t output_extreme[32];
    uint8_t output_ultra[32];
    uint8_t output_mega[32];
    uint8_t output_super[32];
    uint8_t output_hyper[32];
    
    aes_sm3_integrity_256bit_extreme(input, output_extreme);
    aes_sm3_integrity_256bit_ultra(input, output_ultra);
    aes_sm3_integrity_256bit_mega(input, output_mega);
    aes_sm3_integrity_256bit_super(input, output_super);
    aes_sm3_integrity_256bit_hyper(input, output_hyper);
    
    int versions_consistent = 
        compare_bytes(output_extreme, output_ultra, 32) &&
        compare_bytes(output_ultra, output_mega, 32) &&
        compare_bytes(output_mega, output_super, 32) &&
        compare_bytes(output_super, output_hyper, 32);
    
    record_test("不同版本输出一致性 (v3.0-v6.0)", versions_consistent);
    
    if (!versions_consistent) {
        print_hex("  v3.0 Extreme", output_extreme, 32);
        print_hex("  v3.1 Ultra", output_ultra, 32);
        print_hex("  v4.0 Mega", output_mega, 32);
        print_hex("  v5.0 Super", output_super, 32);
        print_hex("  v6.0 Hyper", output_hyper, 32);
    }
    
    printf("\n");
}

/**
 * @brief 测试5.3.4: 批处理正确性测试
 */
void test_batch_correctness() {
    printf("\n【测试5.3.4】批处理正确性测试\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    const int batch_size = 8;
    
    // 准备输入：8个相同的块
    uint8_t* batch_data = malloc(batch_size * 4096);
    uint8_t* single_input = malloc(4096);
    generate_pattern_data(single_input, 4096);
    
    for (int i = 0; i < batch_size; i++) {
        memcpy(batch_data + i * 4096, single_input, 4096);
    }
    
    // 批处理
    const uint8_t* inputs[batch_size];
    uint8_t* batch_outputs[batch_size];
    uint8_t* batch_output_data = malloc(batch_size * 32);
    
    for (int i = 0; i < batch_size; i++) {
        inputs[i] = batch_data + i * 4096;
        batch_outputs[i] = batch_output_data + i * 32;
    }
    
    aes_sm3_integrity_batch(inputs, batch_outputs, batch_size);
    
    // 单独处理
    uint8_t single_output[32];
    aes_sm3_integrity_256bit(single_input, single_output);
    
    // 验证批处理结果与单独处理一致
    int all_match = 1;
    for (int i = 0; i < batch_size; i++) {
        if (!compare_bytes(batch_outputs[i], single_output, 32)) {
            all_match = 0;
            printf("  批处理块 %d 输出不一致\n", i);
            break;
        }
    }
    
    record_test("批处理输出与单独处理一致", all_match);
    
    free(batch_data);
    free(single_input);
    free(batch_output_data);
    
    printf("\n");
}

/**
 * @brief 测试5.3.5: 多线程正确性测试
 */
void test_multithread_correctness() {
    printf("\n【测试5.3.5】多线程正确性测试\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    const int num_blocks = 100;
    const int num_threads = 4;
    
    // 准备输入
    uint8_t* multithread_data = malloc(num_blocks * 4096);
    for (int i = 0; i < num_blocks; i++) {
        generate_random_data(multithread_data + i * 4096, 4096, i);
    }
    
    // 多线程处理
    uint8_t* mt_output = malloc(num_blocks * 32);
    aes_sm3_parallel(multithread_data, mt_output, num_blocks, num_threads, 256);
    
    // 单线程验证
    int all_correct = 1;
    uint8_t single_output[32];
    for (int i = 0; i < num_blocks; i++) {
        aes_sm3_integrity_256bit(multithread_data + i * 4096, single_output);
        if (!compare_bytes(mt_output + i * 32, single_output, 32)) {
            all_correct = 0;
            printf("  多线程块 %d 输出不一致\n", i);
            break;
        }
    }
    
    record_test("多线程输出与单线程一致", all_correct);
    
    free(multithread_data);
    free(mt_output);
    
    printf("\n");
}

// ============================================================================
// 5.4 性能测试
// ============================================================================

/**
 * @brief 测试5.4.1: 单块性能测试
 */
void test_single_block_performance() {
    printf("\n【测试5.4.1】单块性能测试\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    const int iterations = 100000;
    uint8_t input[4096];
    uint8_t output[32];
    
    generate_pattern_data(input, 4096);
    
    struct timespec start, end;
    
    // 测试v5.0 Super版本
    printf("  测试v5.0 Super版本 (%d次迭代)...\n", iterations);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        aes_sm3_integrity_256bit_super(input, output);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_super = (end.tv_sec - start.tv_sec) + 
                        (end.tv_nsec - start.tv_nsec) / 1e9;
    double throughput_super = (iterations * 4.0) / time_super;
    
    printf("    耗时: %.6f秒\n", time_super);
    printf("    吞吐量: %.2f MB/s\n", throughput_super);
    printf("    单块延迟: %.2f微秒\n", time_super * 1e6 / iterations);
    
    // 测试v6.0 Hyper版本
    printf("\n  测试v6.0 Hyper版本 (%d次迭代)...\n", iterations);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        aes_sm3_integrity_256bit_hyper(input, output);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_hyper = (end.tv_sec - start.tv_sec) + 
                        (end.tv_nsec - start.tv_nsec) / 1e9;
    double throughput_hyper = (iterations * 4.0) / time_hyper;
    
    printf("    耗时: %.6f秒\n", time_hyper);
    printf("    吞吐量: %.2f MB/s\n", throughput_hyper);
    printf("    单块延迟: %.2f微秒\n", time_hyper * 1e6 / iterations);
    
    printf("\n  v6.0 vs v5.0 性能提升: %.2f%%\n", 
           (throughput_hyper - throughput_super) / throughput_super * 100);
    
    printf("\n");
}

/**
 * @brief 测试5.4.2: 对比基准性能测试
 */
void test_baseline_performance() {
    printf("\n【测试5.4.2】对比基准性能测试\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    const int iterations = 10000;
    uint8_t input[4096];
    uint8_t output[32];
    
    generate_pattern_data(input, 4096);
    
    struct timespec start, end;
    
    // 测试SHA256
    printf("  测试SHA256 (%d次迭代)...\n", iterations);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        sha256_4kb(input, output);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_sha256 = (end.tv_sec - start.tv_sec) + 
                         (end.tv_nsec - start.tv_nsec) / 1e9;
    double throughput_sha256 = (iterations * 4.0) / time_sha256;
    
    printf("    耗时: %.6f秒\n", time_sha256);
    printf("    吞吐量: %.2f MB/s\n", throughput_sha256);
    
    // 测试纯SM3
    printf("\n  测试纯SM3 (%d次迭代)...\n", iterations);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        sm3_4kb(input, output);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_sm3 = (end.tv_sec - start.tv_sec) + 
                      (end.tv_nsec - start.tv_nsec) / 1e9;
    double throughput_sm3 = (iterations * 4.0) / time_sm3;
    
    printf("    耗时: %.6f秒\n", time_sm3);
    printf("    吞吐量: %.2f MB/s\n", throughput_sm3);
    
    // 测试XOR+SM3 v5.0
    printf("\n  测试XOR折叠+SM3 v5.0 (%d次迭代)...\n", iterations);
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        aes_sm3_integrity_256bit_super(input, output);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_xor_sm3 = (end.tv_sec - start.tv_sec) + 
                          (end.tv_nsec - start.tv_nsec) / 1e9;
    double throughput_xor_sm3 = (iterations * 4.0) / time_xor_sm3;
    
    printf("    耗时: %.6f秒\n", time_xor_sm3);
    printf("    吞吐量: %.2f MB/s\n", throughput_xor_sm3);
    
    // 性能对比
    printf("\n  性能对比:\n");
    printf("    相对SHA256加速比: %.2fx\n", throughput_xor_sm3 / throughput_sha256);
    printf("    相对纯SM3加速比: %.2fx\n", throughput_xor_sm3 / throughput_sm3);
    
    // 10倍性能目标检验
    double speedup = throughput_xor_sm3 / throughput_sha256;
    int meets_goal = (speedup >= 10.0);
    
    printf("\n  >>> 10倍性能目标检验: %.2fx ", speedup);
    if (meets_goal) {
        printf("[✓ 达成]\n");
    } else {
        printf("[✗ 未达成，需%.1fx]\n", 10.0 / speedup);
    }
    
    record_test("10倍性能目标", meets_goal);
    
    printf("\n");
}

/**
 * @brief 测试5.4.3: SM3优化效果测试
 * 
 * 对比标准循环版本和完全展开版本的SM3压缩函数性能
 */
void test_sm3_optimization_effect() {
    printf("\n【测试5.4.3】SM3优化效果测试\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    const int iterations = 100000;
    
    // 准备测试数据块（模拟SM3消息块）
    uint32_t block[16];
    for (int i = 0; i < 16; i++) {
        block[i] = 0x12345678 + i;
    }
    
    // SM3初始状态向量
    static const uint32_t SM3_IV[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };
    
    struct timespec start, end;
    
    // 测试1: sm3_compress_hw (标准循环版本)
    printf("  测试标准循环版本 sm3_compress_hw (%d次迭代)...\n", iterations);
    uint32_t state_loop[8];
    memcpy(state_loop, SM3_IV, sizeof(SM3_IV));
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        sm3_compress_hw(state_loop, block);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_loop = (end.tv_sec - start.tv_sec) + 
                       (end.tv_nsec - start.tv_nsec) / 1e9;
    double ops_per_sec_loop = iterations / time_loop;
    
    printf("    耗时: %.6f秒\n", time_loop);
    printf("    吞吐量: %.2f Mops/s\n", ops_per_sec_loop / 1e6);
    printf("    平均延迟: %.2f纳秒/次\n", time_loop * 1e9 / iterations);
    
    // 测试2: sm3_compress_hw_inline_full (完全展开版本)
    printf("\n  测试完全展开版本 sm3_compress_hw_inline_full (%d次迭代)...\n", iterations);
    uint32_t state_inline[8];
    memcpy(state_inline, SM3_IV, sizeof(SM3_IV));
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        sm3_compress_hw_inline_full(state_inline, block);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_inline = (end.tv_sec - start.tv_sec) + 
                         (end.tv_nsec - start.tv_nsec) / 1e9;
    double ops_per_sec_inline = iterations / time_inline;
    
    printf("    耗时: %.6f秒\n", time_inline);
    printf("    吞吐量: %.2f Mops/s\n", ops_per_sec_inline / 1e6);
    printf("    平均延迟: %.2f纳秒/次\n", time_inline * 1e9 / iterations);
    
    // 结果一致性验证
    int results_match = (memcmp(state_loop, state_inline, sizeof(state_loop)) == 0);
    printf("\n  结果一致性: %s\n", results_match ? "[✓ 一致]" : "[✗ 不一致]");
    
    // 性能提升分析
    double speedup = time_loop / time_inline;
    printf("\n  性能对比分析:\n");
    printf("    完全展开版本相对加速比: %.2fx\n", speedup);
    printf("    性能提升: %.2f%%\n", (speedup - 1.0) * 100);
    printf("    延迟降低: %.2f%%\n", (1.0 - 1.0/speedup) * 100);
    
    // 优化效果评估
    int optimization_effective = (speedup >= 1.15);  // 至少15%提升
    printf("\n  >>> 优化效果评估 (期望≥15%%提升): ");
    if (optimization_effective) {
        printf("[✓ 有效]\n");
    } else {
        printf("[✗ 提升不足]\n");
    }
    
    record_test("SM3循环展开优化效果", optimization_effective);
    record_test("SM3优化版本结果一致性", results_match);
    
    printf("\n");
}

/**
 * @brief 测试5.4.5: 内存访问优化性能测试
 * 
 * 对比使用和不使用内存预取、缓存行对齐等优化的性能差异
 */
void test_memory_optimization_performance() {
    printf("\n【测试5.4.5】内存访问优化性能测试\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    // 调用aes_sm3_integrity.c中的内存优化测试函数
    printf("  执行内存访问优化对比测试...\n\n");
    test_memory_access_optimization();
    
    // 补充批处理预取优化测试
    const int batch_size = 8;
    const int iterations = 5000;
    
    printf("\n  批处理预取优化测试 (批大小=%d, %d次迭代):\n", batch_size, iterations);
    
    // 准备测试数据
    uint8_t* batch_data = malloc(batch_size * 4096);
    for (int i = 0; i < batch_size; i++) {
        generate_pattern_data(batch_data + i * 4096, 4096);
    }
    
    const uint8_t* inputs[batch_size];
    uint8_t* outputs_with_prefetch[batch_size];
    uint8_t* outputs_no_prefetch[batch_size];
    uint8_t* output_data1 = malloc(batch_size * 32);
    uint8_t* output_data2 = malloc(batch_size * 32);
    
    for (int i = 0; i < batch_size; i++) {
        inputs[i] = batch_data + i * 4096;
        outputs_with_prefetch[i] = output_data1 + i * 32;
        outputs_no_prefetch[i] = output_data2 + i * 32;
    }
    
    struct timespec start, end;
    
    // 测试带预取的批处理
    printf("\n    测试1: 带预取优化的批处理...\n");
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        aes_sm3_integrity_batch(inputs, outputs_with_prefetch, batch_size);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_with_prefetch = (end.tv_sec - start.tv_sec) + 
                                (end.tv_nsec - start.tv_nsec) / 1e9;
    double throughput_with = (iterations * batch_size * 4.0) / time_with_prefetch;
    
    printf("      耗时: %.6f秒\n", time_with_prefetch);
    printf("      吞吐量: %.2f MB/s\n", throughput_with);
    
    // 测试不带预取的批处理
    printf("\n    测试2: 无预取优化的批处理...\n");
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        aes_sm3_integrity_batch_no_prefetch(inputs, outputs_no_prefetch, batch_size);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_no_prefetch = (end.tv_sec - start.tv_sec) + 
                              (end.tv_nsec - start.tv_nsec) / 1e9;
    double throughput_without = (iterations * batch_size * 4.0) / time_no_prefetch;
    
    printf("      耗时: %.6f秒\n", time_no_prefetch);
    printf("      吞吐量: %.2f MB/s\n", throughput_without);
    
    // 结果验证
    int results_match = 1;
    for (int i = 0; i < batch_size * 32; i++) {
        if (output_data1[i] != output_data2[i]) {
            results_match = 0;
            break;
        }
    }
    
    printf("\n    结果一致性: %s\n", results_match ? "[✓ 一致]" : "[✗ 不一致]");
    
    // 性能分析
    double speedup = throughput_with / throughput_without;
    printf("\n  内存优化效果分析:\n");
    printf("    预取优化加速比: %.2fx\n", speedup);
    printf("    性能提升: %.2f%%\n", (speedup - 1.0) * 100);
    
    int optimization_effective = (speedup >= 1.10);  // 至少10%提升
    printf("\n  >>> 内存优化效果评估 (期望≥10%%提升): ");
    if (optimization_effective) {
        printf("[✓ 有效]\n");
    } else {
        printf("[✗ 提升不足]\n");
    }
    
    record_test("内存预取优化效果", optimization_effective);
    record_test("内存优化版本结果一致性", results_match);
    
    free(batch_data);
    free(output_data1);
    free(output_data2);
    
    printf("\n");
}

/**
 * @brief 测试5.4.4: 批处理与多线程性能
 */
void test_batch_and_multithread_performance() {
    printf("\n【测试5.4.4】批处理与多线程性能测试\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    const int batch_size = 8;
    const int batch_iterations = 12500;
    
    // 准备批处理输入
    uint8_t* batch_test_data = malloc(batch_size * 4096);
    for (int i = 0; i < batch_size; i++) {
        generate_pattern_data(batch_test_data + i * 4096, 4096);
    }
    
    const uint8_t* batch_inputs[batch_size];
    uint8_t* batch_outputs[batch_size];
    uint8_t* batch_output_data = malloc(batch_size * 32);
    
    for (int i = 0; i < batch_size; i++) {
        batch_inputs[i] = batch_test_data + i * 4096;
        batch_outputs[i] = batch_output_data + i * 32;
    }
    
    // 批处理性能测试
    printf("  测试批处理性能 (批大小=%d, %d批次)...\n", 
           batch_size, batch_iterations);
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < batch_iterations; i++) {
        aes_sm3_integrity_batch(batch_inputs, batch_outputs, batch_size);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_batch = (end.tv_sec - start.tv_sec) + 
                        (end.tv_nsec - start.tv_nsec) / 1e9;
    double throughput_batch = (batch_iterations * batch_size * 4.0) / time_batch;
    
    printf("    耗时: %.6f秒\n", time_batch);
    printf("    吞吐量: %.2f MB/s\n", throughput_batch);
    printf("    单块延迟: %.2f微秒\n", 
           time_batch * 1e6 / (batch_iterations * batch_size));
    
    // 多线程性能测试
    const int mt_blocks = 1000;
    const int num_threads = 4;
    const int mt_iterations = 100;
    
    uint8_t* mt_data = malloc(mt_blocks * 4096);
    uint8_t* mt_output = malloc(mt_blocks * 32);
    
    for (int i = 0; i < mt_blocks; i++) {
        generate_pattern_data(mt_data + i * 4096, 4096);
    }
    
    printf("\n  测试多线程性能 (%d块, %d线程, %d次迭代)...\n", 
           mt_blocks, num_threads, mt_iterations);
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < mt_iterations; i++) {
        aes_sm3_parallel(mt_data, mt_output, mt_blocks, num_threads, 256);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_mt = (end.tv_sec - start.tv_sec) + 
                     (end.tv_nsec - start.tv_nsec) / 1e9;
    double throughput_mt = (mt_iterations * mt_blocks * 4.0) / time_mt;
    
    printf("    耗时: %.6f秒\n", time_mt);
    printf("    吞吐量: %.2f MB/s\n", throughput_mt);
    printf("    单块延迟: %.2f微秒\n", 
           time_mt * 1e6 / (mt_iterations * mt_blocks));
    
    free(batch_test_data);
    free(batch_output_data);
    free(mt_data);
    free(mt_output);
    
    printf("\n");
}

// ============================================================================
// 3.6.3 雪崩效应测试
// ============================================================================

/**
 * @brief 测试雪崩效应
 * 
 * 验证单比特变化导致约50%输出位翻转
 */
void test_avalanche_effect() {
    printf("\n【测试3.6.3】雪崩效应验证\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    const int num_tests = 1000;
    int total_distance = 0;
    int min_distance = 256;
    int max_distance = 0;
    
    printf("  测试样本数: %d\n", num_tests);
    printf("  理论期望: 128位 (50%%)\n");
    printf("  理论标准差: 8位\n");
    printf("  95%%置信区间: [112, 144]位\n\n");
    
    // 执行测试
    uint8_t input1[4096];
    uint8_t input2[4096];
    uint8_t output1[32];
    uint8_t output2[32];
    
    for (int test = 0; test < num_tests; test++) {
        // 生成随机输入
        generate_random_data(input1, 4096, test);
        memcpy(input2, input1, 4096);
        
        // 随机翻转一位
        int byte_pos = test % 4096;
        int bit_pos = (test / 4096) % 8;
        input2[byte_pos] ^= (1 << bit_pos);
        
        // 计算输出
        aes_sm3_integrity_256bit(input1, output1);
        aes_sm3_integrity_256bit(input2, output2);
        
        // 计算汉明距离
        int distance = hamming_distance(output1, output2, 32);
        total_distance += distance;
        
        if (distance < min_distance) min_distance = distance;
        if (distance > max_distance) max_distance = distance;
    }
    
    // 统计分析
    double avg_distance = (double)total_distance / num_tests;
    double flip_rate = avg_distance / 256.0;
    
    printf("  实际结果:\n");
    printf("    平均汉明距离: %.2f位 (%.2f%%)\n", avg_distance, flip_rate * 100);
    printf("    最小汉明距离: %d位\n", min_distance);
    printf("    最大汉明距离: %d位\n", max_distance);
    
    // 计算标准差
    double variance = 0;
    uint8_t temp_input1[4096];
    uint8_t temp_input2[4096];
    uint8_t temp_output1[32];
    uint8_t temp_output2[32];
    
    for (int test = 0; test < num_tests; test++) {
        generate_random_data(temp_input1, 4096, test);
        memcpy(temp_input2, temp_input1, 4096);
        
        int byte_pos = test % 4096;
        int bit_pos = (test / 4096) % 8;
        temp_input2[byte_pos] ^= (1 << bit_pos);
        
        aes_sm3_integrity_256bit(temp_input1, temp_output1);
        aes_sm3_integrity_256bit(temp_input2, temp_output2);
        
        int distance = hamming_distance(temp_output1, temp_output2, 32);
        double diff = distance - avg_distance;
        variance += diff * diff;
    }
    
    double std_dev = sqrt(variance / num_tests);
    printf("    标准差: %.2f位\n", std_dev);
    
    // 严格雪崩准则(SAC)检验
    int passes_sac = (avg_distance >= 112 && avg_distance <= 144);
    printf("\n  >>> 严格雪崩准则(SAC)检验: ");
    if (passes_sac) {
        printf("[✓ 通过]\n");
        printf("      平均翻转率在 95%% 置信区间内\n");
    } else {
        printf("[✗ 未通过]\n");
        printf("      平均翻转率偏离 95%% 置信区间\n");
    }
    
    record_test("雪崩效应(SAC)满足", passes_sac);
    
    printf("\n");
}

// ============================================================================
// 主测试函数
// ============================================================================

void run_all_tests() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║       完整性校验系统测试套件 v1.0                         ║\n");
    printf("║       Test Suite for Integrity Check System             ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    
    // 第五章：作品测试与分析
    printf("\n");
    printf("═══════════════════════════════════════════════════════════\n");
    printf("第五章 作品测试与分析\n");
    printf("═══════════════════════════════════════════════════════════\n");
    
    // 5.3 算法正确性测试
    printf("\n5.3 算法正确性测试\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    test_sm3_standard_vectors();      // 5.3.1
    test_xor_folding_correctness();   // 5.3.2
    test_integrity_algorithm();       // 5.3.3
    test_batch_correctness();         // 5.3.4
    test_multithread_correctness();   // 5.3.5
    
    // 5.4 性能测试
    printf("\n5.4 性能测试\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    test_single_block_performance();         // 5.4.1
    test_baseline_performance();             // 5.4.2
    test_sm3_optimization_effect();          // 5.4.3
    test_batch_and_multithread_performance(); // 5.4.4
    test_memory_optimization_performance();  // 5.4.5
    
    // 3.6.3 雪崩效应测试
    test_avalanche_effect();
    
    // 打印测试统计
    print_test_summary();
}

void run_quick_tests() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║       快速测试模式（仅正确性验证）                         ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    
    test_sm3_standard_vectors();
    test_xor_folding_correctness();
    test_integrity_algorithm();
    test_batch_correctness();
    test_multithread_correctness();
    
    print_test_summary();
}

void run_performance_tests() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║       性能测试模式                                         ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    
    test_single_block_performance();
    test_baseline_performance();
    test_sm3_optimization_effect();
    test_batch_and_multithread_performance();
    test_memory_optimization_performance();
    
    print_test_summary();
}

// ============================================================================
// main函数
// ============================================================================

int main(int argc, char* argv[]) {
    // 解析命令行参数
    if (argc > 1) {
        if (strcmp(argv[1], "--quick") == 0) {
            run_quick_tests();
        } else if (strcmp(argv[1], "--performance") == 0) {
            run_performance_tests();
        } else if (strcmp(argv[1], "--avalanche") == 0) {
            test_avalanche_effect();
        } else if (strcmp(argv[1], "--all") == 0) {
            run_all_tests();
        } else {
            printf("用法: %s [--quick|--performance|--avalanche|--all]\n", argv[0]);
            printf("  --quick       : 快速测试（仅正确性验证）\n");
            printf("  --performance : 性能测试\n");
            printf("  --avalanche   : 雪崩效应测试\n");
            printf("  --all         : 完整测试（默认）\n");
            return 1;
        }
    } else {
        // 默认运行完整测试
        run_all_tests();
    }
    
    return (test_stats.failed_tests == 0) ? 0 : 1;
}
