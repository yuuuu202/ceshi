/*
 * ============================================================================
 * 测试数据生成工具
 * 文件名：generate_test_data.c
 * 
 * 功能：为完整性校验系统生成各种测试数据
 * 包含：标准测试向量、随机数据、边界数据、雪崩测试数据等
 * 
 * 编译命令：
 * gcc -O2 -o generate_test_data generate_test_data.c -lm
 * 
 * 运行命令：
 * ./generate_test_data [输出目录]
 * 
 * 输出文件：
 * - test_data_zeros.bin      : 全0数据（4KB）
 * - test_data_ones.bin       : 全1数据（4KB）
 * - test_data_pattern.bin    : 模式数据（0x00-0xFF循环，4KB）
 * - test_data_random_*.bin   : 随机数据（多个文件，每个4KB）
 * - test_data_avalanche.bin  : 雪崩测试数据对（1000对，每对8KB）
 * - test_data_batch.bin      : 批处理测试数据（64KB = 16个4KB块）
 * - test_vectors.txt         : 标准测试向量和期望输出
 * 
 * 版本：v1.0
 * 日期：2025-10-22
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BLOCK_SIZE 4096

/**
 * @brief 创建输出目录
 */
int create_output_directory(const char* dir) {
#ifdef _WIN32
    return mkdir(dir);
#else
    return mkdir(dir, 0755);
#endif
}

/**
 * @brief 写入二进制文件
 */
int write_binary_file(const char* filename, const uint8_t* data, size_t size) {
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "错误：无法创建文件 %s\n", filename);
        return -1;
    }
    
    size_t written = fwrite(data, 1, size, fp);
    fclose(fp);
    
    if (written != size) {
        fprintf(stderr, "错误：写入文件 %s 失败\n", filename);
        return -1;
    }
    
    printf("✓ 已生成: %s (%zu 字节)\n", filename, size);
    return 0;
}

/**
 * @brief 生成全0数据
 */
void generate_zeros_data(const char* output_dir) {
    uint8_t data[BLOCK_SIZE];
    memset(data, 0, BLOCK_SIZE);
    
    char filename[256];
    snprintf(filename, sizeof(filename), "%s/test_data_zeros.bin", output_dir);
    write_binary_file(filename, data, BLOCK_SIZE);
}

/**
 * @brief 生成全1数据
 */
void generate_ones_data(const char* output_dir) {
    uint8_t data[BLOCK_SIZE];
    memset(data, 0xFF, BLOCK_SIZE);
    
    char filename[256];
    snprintf(filename, sizeof(filename), "%s/test_data_ones.bin", output_dir);
    write_binary_file(filename, data, BLOCK_SIZE);
}

/**
 * @brief 生成模式数据（0x00-0xFF循环）
 */
void generate_pattern_data(const char* output_dir) {
    uint8_t data[BLOCK_SIZE];
    
    for (int i = 0; i < BLOCK_SIZE; i++) {
        data[i] = i % 256;
    }
    
    char filename[256];
    snprintf(filename, sizeof(filename), "%s/test_data_pattern.bin", output_dir);
    write_binary_file(filename, data, BLOCK_SIZE);
}

/**
 * @brief 生成随机数据
 */
void generate_random_data(const char* output_dir, int count) {
    printf("\n生成随机数据 (%d 个文件)...\n", count);
    
    for (int i = 0; i < count; i++) {
        uint8_t data[BLOCK_SIZE];
        
        // 使用不同的种子生成不同的随机数据
        srand(time(NULL) + i);
        
        for (int j = 0; j < BLOCK_SIZE; j++) {
            data[j] = rand() & 0xFF;
        }
        
        char filename[256];
        snprintf(filename, sizeof(filename), 
                 "%s/test_data_random_%03d.bin", output_dir, i);
        write_binary_file(filename, data, BLOCK_SIZE);
    }
}

/**
 * @brief 生成雪崩测试数据对
 * 
 * 生成1000对数据，每对中的两个数据块只有1个比特不同
 */
void generate_avalanche_data(const char* output_dir) {
    printf("\n生成雪崩测试数据 (1000 对)...\n");
    
    const int num_pairs = 1000;
    uint8_t* all_data = malloc(num_pairs * 2 * BLOCK_SIZE);
    
    if (!all_data) {
        fprintf(stderr, "错误：内存分配失败\n");
        return;
    }
    
    srand(time(NULL));
    
    for (int i = 0; i < num_pairs; i++) {
        uint8_t* data1 = all_data + (i * 2) * BLOCK_SIZE;
        uint8_t* data2 = all_data + (i * 2 + 1) * BLOCK_SIZE;
        
        // 生成第一个数据块
        for (int j = 0; j < BLOCK_SIZE; j++) {
            data1[j] = rand() & 0xFF;
        }
        
        // 复制到第二个数据块
        memcpy(data2, data1, BLOCK_SIZE);
        
        // 随机翻转一个比特
        int byte_pos = rand() % BLOCK_SIZE;
        int bit_pos = rand() % 8;
        data2[byte_pos] ^= (1 << bit_pos);
    }
    
    char filename[256];
    snprintf(filename, sizeof(filename), 
             "%s/test_data_avalanche.bin", output_dir);
    write_binary_file(filename, all_data, num_pairs * 2 * BLOCK_SIZE);
    
    free(all_data);
}

/**
 * @brief 生成批处理测试数据
 */
void generate_batch_data(const char* output_dir) {
    printf("\n生成批处理测试数据 (16 个块)...\n");
    
    const int num_blocks = 16;
    uint8_t* all_data = malloc(num_blocks * BLOCK_SIZE);
    
    if (!all_data) {
        fprintf(stderr, "错误：内存分配失败\n");
        return;
    }
    
    // 生成16个不同的数据块
    for (int i = 0; i < num_blocks; i++) {
        uint8_t* block = all_data + i * BLOCK_SIZE;
        
        // 每个块使用不同的模式
        for (int j = 0; j < BLOCK_SIZE; j++) {
            block[j] = (i * 256 + j) % 256;
        }
    }
    
    char filename[256];
    snprintf(filename, sizeof(filename), 
             "%s/test_data_batch.bin", output_dir);
    write_binary_file(filename, all_data, num_blocks * BLOCK_SIZE);
    
    free(all_data);
}

/**
 * @brief 生成边界数据
 */
void generate_boundary_data(const char* output_dir) {
    printf("\n生成边界测试数据...\n");
    
    // 交替0和1
    uint8_t data_alternating[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) {
        data_alternating[i] = (i % 2) ? 0xFF : 0x00;
    }
    
    char filename[256];
    snprintf(filename, sizeof(filename), 
             "%s/test_data_alternating.bin", output_dir);
    write_binary_file(filename, data_alternating, BLOCK_SIZE);
    
    // 渐变数据
    uint8_t data_gradient[BLOCK_SIZE];
    for (int i = 0; i < BLOCK_SIZE; i++) {
        data_gradient[i] = (i * 256) / BLOCK_SIZE;
    }
    
    snprintf(filename, sizeof(filename), 
             "%s/test_data_gradient.bin", output_dir);
    write_binary_file(filename, data_gradient, BLOCK_SIZE);
    
    // 前半部分0，后半部分1
    uint8_t data_half[BLOCK_SIZE];
    memset(data_half, 0x00, BLOCK_SIZE / 2);
    memset(data_half + BLOCK_SIZE / 2, 0xFF, BLOCK_SIZE / 2);
    
    snprintf(filename, sizeof(filename), 
             "%s/test_data_half.bin", output_dir);
    write_binary_file(filename, data_half, BLOCK_SIZE);
}

/**
 * @brief 生成SM3标准测试向量描述文件
 */
void generate_test_vectors_file(const char* output_dir) {
    printf("\n生成测试向量描述文件...\n");
    
    char filename[256];
    snprintf(filename, sizeof(filename), "%s/test_vectors.txt", output_dir);
    
    FILE* fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "错误：无法创建文件 %s\n", filename);
        return;
    }
    
    fprintf(fp, "===============================================================================\n");
    fprintf(fp, "完整性校验系统测试向量\n");
    fprintf(fp, "Integrity Check System Test Vectors\n");
    fprintf(fp, "===============================================================================\n\n");
    
    fprintf(fp, "【SM3标准测试向量】(GB/T 32905-2016)\n\n");
    
    fprintf(fp, "测试向量1:\n");
    fprintf(fp, "  输入 (ASCII): \"abc\"\n");
    fprintf(fp, "  输入 (HEX): 616263\n");
    fprintf(fp, "  标准SM3输出:\n");
    fprintf(fp, "    66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0\n\n");
    
    fprintf(fp, "测试向量2:\n");
    fprintf(fp, "  输入 (ASCII): \"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd\"\n");
    fprintf(fp, "  标准SM3输出:\n");
    fprintf(fp, "    debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732\n\n");
    
    fprintf(fp, "===============================================================================\n\n");
    
    fprintf(fp, "【测试数据文件列表】\n\n");
    fprintf(fp, "基础数据:\n");
    fprintf(fp, "  - test_data_zeros.bin       : 全0数据 (4KB)\n");
    fprintf(fp, "  - test_data_ones.bin        : 全1数据 (4KB)\n");
    fprintf(fp, "  - test_data_pattern.bin     : 模式数据 (0x00-0xFF循环, 4KB)\n");
    fprintf(fp, "  - test_data_alternating.bin : 交替0/1数据 (4KB)\n");
    fprintf(fp, "  - test_data_gradient.bin    : 渐变数据 (4KB)\n");
    fprintf(fp, "  - test_data_half.bin        : 前半0后半1 (4KB)\n\n");
    
    fprintf(fp, "随机数据:\n");
    fprintf(fp, "  - test_data_random_XXX.bin  : 随机数据 (多个文件, 每个4KB)\n\n");
    
    fprintf(fp, "批处理数据:\n");
    fprintf(fp, "  - test_data_batch.bin       : 批处理测试数据 (16个4KB块 = 64KB)\n\n");
    
    fprintf(fp, "雪崩测试数据:\n");
    fprintf(fp, "  - test_data_avalanche.bin   : 雪崩测试数据对 (1000对, 每对8KB)\n");
    fprintf(fp, "                                每对中两个块只有1比特不同\n\n");
    
    fprintf(fp, "===============================================================================\n\n");
    
    fprintf(fp, "【使用说明】\n\n");
    fprintf(fp, "1. 正确性测试:\n");
    fprintf(fp, "   使用 test_data_zeros.bin, test_data_ones.bin 等基础数据\n");
    fprintf(fp, "   验证算法的确定性和基本功能\n\n");
    
    fprintf(fp, "2. 雪崩效应测试:\n");
    fprintf(fp, "   使用 test_data_avalanche.bin\n");
    fprintf(fp, "   每对数据（8KB）包含两个相邻的4KB块\n");
    fprintf(fp, "   第一个块: [offset + 0, offset + 4095]\n");
    fprintf(fp, "   第二个块: [offset + 4096, offset + 8191]\n");
    fprintf(fp, "   验证单比特变化导致约50%%输出位翻转\n\n");
    
    fprintf(fp, "3. 批处理测试:\n");
    fprintf(fp, "   使用 test_data_batch.bin\n");
    fprintf(fp, "   包含16个4KB块，可用于批处理功能验证\n\n");
    
    fprintf(fp, "4. 性能测试:\n");
    fprintf(fp, "   使用 test_data_random_XXX.bin\n");
    fprintf(fp, "   多个随机数据文件可用于吞吐量测试\n\n");
    
    fprintf(fp, "===============================================================================\n");
    
    fclose(fp);
    printf("✓ 已生成: %s\n", filename);
}

/**
 * @brief 生成多线程测试数据
 */
void generate_multithread_data(const char* output_dir) {
    printf("\n生成多线程测试数据 (1000 个块)...\n");
    
    const int num_blocks = 1000;
    uint8_t* all_data = malloc(num_blocks * BLOCK_SIZE);
    
    if (!all_data) {
        fprintf(stderr, "错误：内存分配失败\n");
        return;
    }
    
    // 生成1000个不同的数据块
    srand(time(NULL));
    for (int i = 0; i < num_blocks; i++) {
        uint8_t* block = all_data + i * BLOCK_SIZE;
        
        // 每个块使用不同的模式和随机种子
        for (int j = 0; j < BLOCK_SIZE; j++) {
            block[j] = (i + j + rand()) % 256;
        }
    }
    
    char filename[256];
    snprintf(filename, sizeof(filename), 
             "%s/test_data_multithread.bin", output_dir);
    write_binary_file(filename, all_data, num_blocks * BLOCK_SIZE);
    
    free(all_data);
}

/**
 * @brief 生成README文件
 */
void generate_readme(const char* output_dir) {
    printf("\n生成README文件...\n");
    
    char filename[256];
    snprintf(filename, sizeof(filename), "%s/README.txt", output_dir);
    
    FILE* fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "错误：无法创建文件 %s\n", filename);
        return;
    }
    
    fprintf(fp, "===============================================================================\n");
    fprintf(fp, "完整性校验系统测试数据包\n");
    fprintf(fp, "Integrity Check System Test Data Package\n");
    fprintf(fp, "===============================================================================\n\n");
    
    fprintf(fp, "本目录包含完整性校验系统的所有测试数据，用于验证算法的正确性、\n");
    fprintf(fp, "性能和安全性。\n\n");
    
    fprintf(fp, "【目录结构】\n\n");
    fprintf(fp, "test_data/\n");
    fprintf(fp, "├── README.txt                    # 本文件\n");
    fprintf(fp, "├── test_vectors.txt              # 测试向量说明\n");
    fprintf(fp, "├── test_data_zeros.bin           # 全0数据\n");
    fprintf(fp, "├── test_data_ones.bin            # 全1数据\n");
    fprintf(fp, "├── test_data_pattern.bin         # 模式数据\n");
    fprintf(fp, "├── test_data_alternating.bin     # 交替数据\n");
    fprintf(fp, "├── test_data_gradient.bin        # 渐变数据\n");
    fprintf(fp, "├── test_data_half.bin            # 前半后半数据\n");
    fprintf(fp, "├── test_data_random_XXX.bin      # 随机数据（10个文件）\n");
    fprintf(fp, "├── test_data_batch.bin           # 批处理数据\n");
    fprintf(fp, "├── test_data_avalanche.bin       # 雪崩测试数据\n");
    fprintf(fp, "└── test_data_multithread.bin     # 多线程测试数据\n\n");
    
    fprintf(fp, "【测试类型对应数据】\n\n");
    
    fprintf(fp, "1. 正确性测试 (5.3节):\n");
    fprintf(fp, "   - SM3标准向量测试: 参考test_vectors.txt\n");
    fprintf(fp, "   - XOR折叠测试: test_data_zeros.bin, test_data_ones.bin\n");
    fprintf(fp, "   - 完整性算法测试: test_data_pattern.bin\n");
    fprintf(fp, "   - 批处理测试: test_data_batch.bin\n");
    fprintf(fp, "   - 多线程测试: test_data_multithread.bin\n\n");
    
    fprintf(fp, "2. 性能测试 (5.4节):\n");
    fprintf(fp, "   - 单块性能: test_data_pattern.bin\n");
    fprintf(fp, "   - 批处理性能: test_data_batch.bin\n");
    fprintf(fp, "   - 多线程性能: test_data_multithread.bin\n\n");
    
    fprintf(fp, "3. 雪崩效应测试 (3.6.3节):\n");
    fprintf(fp, "   - 雪崩验证: test_data_avalanche.bin\n");
    fprintf(fp, "   - 统计分析: test_data_random_*.bin\n\n");
    
    fprintf(fp, "【数据格式】\n\n");
    fprintf(fp, "- 所有.bin文件都是原始二进制格式\n");
    fprintf(fp, "- 每个基础块大小: 4096字节 (4KB)\n");
    fprintf(fp, "- 批处理数据: 16个连续的4KB块\n");
    fprintf(fp, "- 雪崩测试数据: 1000对连续的4KB块（共8MB）\n");
    fprintf(fp, "- 多线程数据: 1000个连续的4KB块（约4MB）\n\n");
    
    fprintf(fp, "【使用方法】\n\n");
    fprintf(fp, "1. 使用测试套件:\n");
    fprintf(fp, "   cd ..\n");
    fprintf(fp, "   ./test_integrity_suite --all\n\n");
    
    fprintf(fp, "2. 手动加载数据测试:\n");
    fprintf(fp, "   # C代码示例\n");
    fprintf(fp, "   FILE* fp = fopen(\"test_data/test_data_pattern.bin\", \"rb\");\n");
    fprintf(fp, "   uint8_t input[4096];\n");
    fprintf(fp, "   fread(input, 1, 4096, fp);\n");
    fprintf(fp, "   fclose(fp);\n\n");
    
    fprintf(fp, "3. Python脚本读取:\n");
    fprintf(fp, "   with open('test_data/test_data_pattern.bin', 'rb') as f:\n");
    fprintf(fp, "       data = f.read(4096)\n\n");
    
    fprintf(fp, "【数据生成】\n\n");
    fprintf(fp, "所有测试数据由 generate_test_data 工具生成:\n");
    fprintf(fp, "  ./generate_test_data test_data\n\n");
    
    fprintf(fp, "如需重新生成，请删除test_data目录后重新运行上述命令。\n\n");
    
    fprintf(fp, "===============================================================================\n");
    fprintf(fp, "版本: v1.0\n");
    fprintf(fp, "日期: 2025-10-22\n");
    fprintf(fp, "===============================================================================\n");
    
    fclose(fp);
    printf("✓ 已生成: %s\n", filename);
}

// ============================================================================
// main函数
// ============================================================================

int main(int argc, char* argv[]) {
    const char* output_dir = "test_data";
    
    // 解析命令行参数
    if (argc > 1) {
        output_dir = argv[1];
    }
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║       测试数据生成工具 v1.0                               ║\n");
    printf("║       Test Data Generator                                ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    
    printf("\n输出目录: %s\n", output_dir);
    
    // 创建输出目录
    if (create_output_directory(output_dir) != 0) {
        // 目录可能已存在，继续执行
    }
    
    printf("\n开始生成测试数据...\n");
    printf("═══════════════════════════════════════════════════════════\n");
    
    // 生成各类测试数据
    printf("\n[1/9] 生成基础测试数据...\n");
    generate_zeros_data(output_dir);
    generate_ones_data(output_dir);
    generate_pattern_data(output_dir);
    
    printf("\n[2/9] 生成边界测试数据...\n");
    generate_boundary_data(output_dir);
    
    printf("\n[3/9] 生成随机测试数据...\n");
    generate_random_data(output_dir, 10);
    
    printf("\n[4/9] 生成雪崩测试数据...\n");
    generate_avalanche_data(output_dir);
    
    printf("\n[5/9] 生成批处理测试数据...\n");
    generate_batch_data(output_dir);
    
    printf("\n[6/9] 生成多线程测试数据...\n");
    generate_multithread_data(output_dir);
    
    printf("\n[7/9] 生成测试向量文件...\n");
    generate_test_vectors_file(output_dir);
    
    printf("\n[8/9] 生成README文件...\n");
    generate_readme(output_dir);
    
    printf("\n[9/9] 完成!\n");
    
    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("测试数据生成完成！\n");
    printf("═══════════════════════════════════════════════════════════\n\n");
    
    printf("生成的文件列表:\n");
    printf("  - 6个基础测试数据文件\n");
    printf("  - 10个随机测试数据文件\n");
    printf("  - 1个雪崩测试数据文件 (约8MB)\n");
    printf("  - 1个批处理测试数据文件 (64KB)\n");
    printf("  - 1个多线程测试数据文件 (约4MB)\n");
    printf("  - 1个测试向量说明文件\n");
    printf("  - 1个README文件\n");
    printf("\n总计: 约12-13MB测试数据\n\n");
    
    printf("下一步:\n");
    printf("  1. 编译测试套件: gcc -march=armv8.2-a+crypto -O3 -pthread \\\n");
    printf("                       -o test_integrity_suite test_integrity_suite.c \\\n");
    printf("                       aes_sm3_integrity.c -lm\n");
    printf("  2. 运行测试: ./test_integrity_suite --all\n\n");
    
    return 0;
}

