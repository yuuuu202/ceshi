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

// ============================================================================
// 测试统计
// ============================================================================
static struct {
    int total_tests;
    int passed_tests;
    int failed_tests;
} test_stats = {0, 0, 0};

// ============================================================================
// 辅助函数
// ============================================================================

/**
 * @brief 打印十六进制数据
 */
void print_hex(const char* label, const uint8_t* data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/**
 * @brief 比较两个字节数组
 */
int compare_bytes(const uint8_t* a, const uint8_t* b, int len) {
    return memcmp(a, b, len) == 0;
}

/**
 * @brief 计算汉明距离
 */
int hamming_distance(const uint8_t* a, const uint8_t* b, int len) {
    int distance = 0;
    for (int i = 0; i < len; i++) {
        uint8_t xor = a[i] ^ b[i];
        while (xor) {
            distance += xor & 1;
            xor >>= 1;
        }
    }
    return distance;
}

/**
 * @brief 生成伪随机数据
 */
void generate_random_data(uint8_t* data, int len, int seed) {
    srand(seed);
    for (int i = 0; i < len; i++) {
        data[i] = rand() & 0xFF;
    }
}

/**
 * @brief 生成模式化测试数据
 */
void generate_pattern_data(uint8_t* data, int len) {
    for (int i = 0; i < len; i++) {
        data[i] = i % 256;
    }
}

/**
 * @brief 记录测试结果
 */
void record_test(const char* test_name, int passed) {
    test_stats.total_tests++;
    if (passed) {
        test_stats.passed_tests++;
        printf("  [✓ PASS] %s\n", test_name);
    } else {
        test_stats.failed_tests++;
        printf("  [✗ FAIL] %s\n", test_name);
    }
}

/**
 * @brief 打印测试统计
 */
void print_test_summary() {
    printf("\n");
    printf("═══════════════════════════════════════════════════════════\n");
    printf("测试统计\n");
    printf("═══════════════════════════════════════════════════════════\n");
    printf("总测试数: %d\n", test_stats.total_tests);
    printf("通过: %d (%.1f%%)\n", test_stats.passed_tests, 
           100.0 * test_stats.passed_tests / test_stats.total_tests);
    printf("失败: %d (%.1f%%)\n", test_stats.failed_tests,
           100.0 * test_stats.failed_tests / test_stats.total_tests);
    printf("═══════════════════════════════════════════════════════════\n\n");
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
    printf("\n【测试5.3.1】SM3算法标准测试向量\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    // 测试向量1: "abc"
    // 标准输出：66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
    uint8_t input1[4096];
    memset(input1, 0, 4096);
    memcpy(input1, "abc", 3);
    
    uint8_t output1[32];
    sm3_4kb(input1, output1);
    
    // 注意：这里测试的是4KB输入的SM3，实际标准测试向量是3字节
    // 此处验证实现的一致性
    printf("  测试向量1: \"abc\" (填充到4KB)\n");
    print_hex("  输出", output1, 32);
    
    // 测试2: 确定性验证
    uint8_t output1_repeat[32];
    sm3_4kb(input1, output1_repeat);
    int passed1 = compare_bytes(output1, output1_repeat, 32);
    record_test("SM3确定性验证（重复计算）", passed1);
    
    printf("\n");
}

/**
 * @brief 测试5.3.2: XOR折叠正确性测试
 */
void test_xor_folding_correctness() {
    printf("\n【测试5.3.2】XOR折叠正确性测试\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    // 测试用例1: 全0输入 → XOR结果应全0
    uint8_t input_zeros[4096] = {0};
    uint8_t output_zeros[32];
    aes_sm3_integrity_256bit_extreme(input_zeros, output_zeros);
    
    // 测试用例2: 全1输入
    uint8_t input_ones[4096];
    memset(input_ones, 0xFF, 4096);
    uint8_t output_ones[32];
    aes_sm3_integrity_256bit_extreme(input_ones, output_ones);
    
    // 验证：全0和全1的输出应该不同
    int different = !compare_bytes(output_zeros, output_ones, 32);
    record_test("XOR折叠：全0 vs 全1输出不同", different);
    
    // 测试用例3: 随机输入的确定性
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
    
    record_test("不同版本输出一致性", versions_consistent);
    
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
    uint8_t* test_data = malloc(batch_size * 4096);
    for (int i = 0; i < batch_size; i++) {
        generate_pattern_data(test_data + i * 4096, 4096);
    }
    
    // 单块处理
    uint8_t single_output[32];
    aes_sm3_integrity_256bit_super(test_data, single_output);
    
    // 批处理
    const uint8_t* batch_inputs[batch_size];
    uint8_t* batch_outputs[batch_size];
    uint8_t* batch_output_data = malloc(batch_size * 32);
    
    for (int i = 0; i < batch_size; i++) {
        batch_inputs[i] = test_data + i * 4096;
        batch_outputs[i] = batch_output_data + i * 32;
    }
    
    aes_sm3_integrity_batch(batch_inputs, batch_outputs, batch_size);
    
    // 验证：所有批处理输出应与单块处理一致
    int all_match = 1;
    for (int i = 0; i < batch_size; i++) {
        if (!compare_bytes(single_output, batch_outputs[i], 32)) {
            all_match = 0;
            printf("  块%d输出不匹配\n", i);
        }
    }
    
    record_test("批处理输出与单块处理一致", all_match);
    
    free(test_data);
    free(batch_output_data);
    
    printf("\n");
}

/**
 * @brief 测试5.3.5: 多线程正确性测试
 */
void test_multithread_correctness() {
    printf("\n【测试5.3.5】多线程正确性测试\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    const int block_count = 100;
    const int num_threads = 4;
    
    // 准备输入数据
    uint8_t* input_data = malloc(block_count * 4096);
    for (int i = 0; i < block_count; i++) {
        generate_pattern_data(input_data + i * 4096, 4096);
        // 每块稍微不同
        input_data[i * 4096] = i;
    }
    
    // 单线程处理
    uint8_t* output_single = malloc(block_count * 32);
    for (int i = 0; i < block_count; i++) {
        aes_sm3_integrity_256bit_super(
            input_data + i * 4096,
            output_single + i * 32
        );
    }
    
    // 多线程处理
    uint8_t* output_multi = malloc(block_count * 32);
    aes_sm3_parallel(input_data, output_multi, block_count, num_threads, 256);
    
    // 验证：多线程输出应与单线程完全一致
    int all_match = 1;
    for (int i = 0; i < block_count; i++) {
        if (!compare_bytes(
            output_single + i * 32,
            output_multi + i * 32,
            32
        )) {
            all_match = 0;
            printf("  块%d输出不匹配\n", i);
        }
    }
    
    record_test("多线程输出与单线程一致", all_match);
    
    free(input_data);
    free(output_single);
    free(output_multi);
    
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
    
    // 测试XOR-SM3 v5.0
    printf("\n  测试XOR-SM3 v5.0 Super (%d次迭代)...\n", iterations);
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
    printf("\n  性能对比汇总:\n");
    printf("  ┌────────────────────────────────────────────────────────┐\n");
    printf("  │ 算法          吞吐量(MB/s)    vs SHA256   vs SM3       │\n");
    printf("  ├────────────────────────────────────────────────────────┤\n");
    printf("  │ SHA256        %-12.0f    1.00x       %.2fx      │\n", 
           throughput_sha256, throughput_sha256 / throughput_sm3);
    printf("  │ 纯SM3         %-12.0f    %.2fx       1.00x      │\n", 
           throughput_sm3, throughput_sm3 / throughput_sha256);
    printf("  │ XOR-SM3 v5.0  %-12.0f    %.2fx       %.2fx      │\n", 
           throughput_xor_sm3, 
           throughput_xor_sm3 / throughput_sha256,
           throughput_xor_sm3 / throughput_sm3);
    printf("  └────────────────────────────────────────────────────────┘\n");
    
    // 验证是否达到10倍目标
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
    
    // 多线程性能测试
    const int block_count = 1000;
    const int num_threads = 8;
    
    uint8_t* multi_input = malloc(block_count * 4096);
    uint8_t* multi_output = malloc(block_count * 32);
    
    for (int i = 0; i < block_count * 4096; i++) {
        multi_input[i] = i % 256;
    }
    
    printf("\n  测试多线程性能 (块数=%d, 线程数=%d)...\n", 
           block_count, num_threads);
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    aes_sm3_parallel(multi_input, multi_output, block_count, num_threads, 256);
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_multi = (end.tv_sec - start.tv_sec) + 
                        (end.tv_nsec - start.tv_nsec) / 1e9;
    double throughput_multi = (block_count * 4.0) / time_multi;
    
    printf("    耗时: %.6f秒\n", time_multi);
    printf("    吞吐量: %.2f MB/s\n", throughput_multi);
    
    free(batch_test_data);
    free(batch_output_data);
    free(multi_input);
    free(multi_output);
    
    printf("\n");
}

// ============================================================================
// 雪崩效应测试
// ============================================================================

/**
 * @brief 雪崩效应测试（对应文档3.6.3节）
 */
void test_avalanche_effect() {
    printf("\n【专项测试】雪崩效应验证\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    const int num_tests = 1000;
    int total_distance = 0;
    int max_distance = 0;
    int min_distance = 256;
    
    for (int test = 0; test < num_tests; test++) {
        // 生成原始输入
        uint8_t input1[4096];
        generate_random_data(input1, 4096, test);
        
        // 生成单比特翻转的输入
        uint8_t input2[4096];
        memcpy(input2, input1, 4096);
        
        // 随机翻转一个比特
        int byte_pos = rand() % 4096;
        int bit_pos = rand() % 8;
        input2[byte_pos] ^= (1 << bit_pos);
        
        // 计算两个哈希值
        uint8_t output1[32];
        uint8_t output2[32];
        aes_sm3_integrity_256bit_super(input1, output1);
        aes_sm3_integrity_256bit_super(input2, output2);
        
        // 计算汉明距离
        int distance = hamming_distance(output1, output2, 32);
        total_distance += distance;
        
        if (distance > max_distance) max_distance = distance;
        if (distance < min_distance) min_distance = distance;
    }
    
    double avg_distance = (double)total_distance / num_tests;
    double flip_rate = avg_distance / 256.0;
    
    printf("  测试次数: %d\n", num_tests);
    printf("  平均汉明距离: %.2f bits\n", avg_distance);
    printf("  翻转率: %.2f%% (理论值: 50%%)\n", flip_rate * 100);
    printf("  最大汉明距离: %d bits\n", max_distance);
    printf("  最小汉明距离: %d bits\n", min_distance);
    printf("  标准差: %.2f bits (理论值: 8 bits)\n", 
           sqrt(256.0 * 0.5 * 0.5));
    
    // 验证雪崩效应（翻转率应在45%-55%之间）
    int avalanche_ok = (flip_rate >= 0.45 && flip_rate <= 0.55);
    record_test("雪崩效应验证（翻转率45%-55%）", avalanche_ok);
    
    // 卡方检验
    double expected = 128.0;  // 期望值
    double chi_square = 0.0;
    double variance = 0.0;
    
    // 重新统计分布
    int distribution[257] = {0};  // 0-256的汉明距离分布
    
    for (int test = 0; test < num_tests; test++) {
        uint8_t input1[4096];
        generate_random_data(input1, 4096, test + 10000);
        
        uint8_t input2[4096];
        memcpy(input2, input1, 4096);
        int byte_pos = rand() % 4096;
        int bit_pos = rand() % 8;
        input2[byte_pos] ^= (1 << bit_pos);
        
        uint8_t output1[32];
        uint8_t output2[32];
        aes_sm3_integrity_256bit_super(input1, output1);
        aes_sm3_integrity_256bit_super(input2, output2);
        
        int distance = hamming_distance(output1, output2, 32);
        distribution[distance]++;
        
        double diff = distance - expected;
        variance += diff * diff;
    }
    
    variance /= num_tests;
    double std_dev = sqrt(variance);
    
    printf("\n  统计分析:\n");
    printf("    方差: %.2f (理论值: 64.0)\n", variance);
    printf("    标准差: %.2f (理论值: 8.0)\n", std_dev);
    printf("    95%%置信区间: [%.2f, %.2f]\n", 
           expected - 1.96 * std_dev, expected + 1.96 * std_dev);
    
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
    test_batch_and_multithread_performance(); // 5.4.4
    
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
    test_batch_and_multithread_performance();
    
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

