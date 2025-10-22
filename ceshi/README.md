# 完整性校验系统测试套件

Integrity Check System Test Suite

## 📂 目录结构

```
ceshi/
├── README.md                    # 本文件
├── Makefile                     # 编译和测试脚本
├── test_integrity_suite.c       # 完整测试套件（正确性+性能测试）
├── generate_test_data.c         # 测试数据生成工具
└── test_data/                   # 测试数据目录（运行后生成）
    ├── README.txt
    ├── test_vectors.txt
    └── *.bin                    # 各类测试数据文件
```

## 🚀 快速开始

### 编译指令

**在Windows系统上**（假设已安装GCC/MinGW）：

```bash
# 编译测试套件
gcc -O3 -pthread -o test_integrity_suite.exe test_integrity_suite.c ../cn_test1.1/test1.1/aes_sm3_integrity.c -lm

# 编译测试数据生成器
gcc -O2 -o generate_test_data.exe generate_test_data.c -lm
```

**在Linux/ARM平台上**（推荐）：

```bash
# 编译测试套件（带ARM优化）
gcc -march=armv8.2-a+crypto -O3 -pthread -o test_integrity_suite test_integrity_suite.c ../cn_test1.1/test1.1/aes_sm3_integrity.c -lm

# 编译测试数据生成器
gcc -O2 -o generate_test_data generate_test_data.c -lm
```

**使用Makefile**（Linux/Unix系统）：

```bash
make all
```

### 运行测试

```bash
# Windows
test_integrity_suite.exe --all

# Linux
./test_integrity_suite --all
```

## 📝 详细编译说明

### 1. 编译测试套件

**完整命令**：
```bash
gcc -march=armv8.2-a+crypto -O3 -pthread \
    -o test_integrity_suite \
    test_integrity_suite.c \
    ../cn_test1.1/test1.1/aes_sm3_integrity.c \
    -lm
```

**参数说明**：
- `-march=armv8.2-a+crypto`: ARM架构优化（仅ARM平台）
- `-O3`: 最高级别优化
- `-pthread`: 启用多线程支持
- `-lm`: 链接数学库（用于sqrt等函数）

**Windows简化版本**（不支持ARM优化）：
```bash
gcc -O3 -pthread -o test_integrity_suite.exe test_integrity_suite.c ..\cn_test1.1\test1.1\aes_sm3_integrity.c -lm
```

### 2. 编译测试数据生成器

```bash
gcc -O2 -o generate_test_data generate_test_data.c -lm
```

### 3. 生成测试数据

```bash
# Windows
generate_test_data.exe test_data

# Linux
./generate_test_data test_data
```

这将生成约12-13MB的测试数据到 `test_data/` 目录。

## 🧪 测试选项

### 完整测试（推荐）

```bash
./test_integrity_suite --all
```

包含所有测试项目：
- ✅ SM3算法标准测试向量验证
- ✅ XOR折叠正确性测试
- ✅ 完整性校验算法测试
- ✅ 批处理正确性测试
- ✅ 多线程正确性测试
- ⚡ 单块性能测试
- ⚡ 对比基准性能测试
- ⚡ 批处理与多线程性能测试
- 🔐 雪崩效应验证

### 快速测试（仅正确性验证）

```bash
./test_integrity_suite --quick
```

只运行正确性测试，约1分钟完成。

### 性能测试

```bash
./test_integrity_suite --performance
```

只运行性能测试，验证**10倍于SHA256**的性能目标。

### 雪崩效应测试

```bash
./test_integrity_suite --avalanche
```

验证密码学雪崩效应（单比特变化导致约50%输出位翻转）。

## 📊 测试内容

### 5.3 算法正确性测试

| 测试项 | 描述 |
|--------|------|
| 5.3.1 | SM3算法标准测试向量（GB/T 32905-2016） |
| 5.3.2 | XOR折叠正确性（全0、全1、随机输入） |
| 5.3.3 | 完整性校验算法（256位/128位输出、版本一致性） |
| 5.3.4 | 批处理正确性 |
| 5.3.5 | 多线程正确性 |

### 5.4 性能测试

| 测试项 | 描述 | 目标 |
|--------|------|------|
| 5.4.1 | 单块性能 | 测试v5.0和v6.0版本吞吐量 |
| 5.4.2 | 对比基准 | **验证10倍于SHA256的性能目标** |
| 5.4.4 | 批处理&多线程 | 测试并行处理性能提升 |

### 3.6.3 雪崩效应测试

- 1000次单比特翻转测试
- 汉明距离统计分析
- 卡方检验
- 验证翻转率在45%-55%范围内

## 🔧 系统要求

### 推荐环境（最佳性能）

- **硬件平台**: ARMv8.2-A或更高（支持crypto扩展）
- **操作系统**: Linux（Ubuntu 20.04+/CentOS 8+）
- **编译器**: GCC 7.0+
- **依赖库**: pthread, math library

### Windows环境

- **编译器**: MinGW-w64 或 GCC for Windows
- **说明**: 不支持ARM优化，性能测试结果仅供参考

### 注意事项

⚠️ **重要提示**：
1. 在非ARM64平台上编译会有警告，某些硬件加速功能将无法使用
2. 性能测试结果因硬件配置而异
3. 建议在真实ARM硬件上运行以获得最佳性能和准确的测试结果

## 📦 使用Makefile（Linux/Unix）

```bash
# 编译所有程序并生成测试数据
make all

# 运行测试
make test-all          # 完整测试
make test-quick        # 快速测试
make test-performance  # 性能测试
make test-avalanche    # 雪崩测试

# 清理
make clean             # 清理编译文件
make clean-data        # 清理测试数据
make clean-all         # 清理所有文件

# 帮助
make help              # 显示帮助信息
make info              # 显示平台信息
```

## 📈 测试报告

测试完成后，将输出：

### 1. 测试统计
- 总测试数
- 通过数量和百分比
- 失败数量和百分比

### 2. 性能指标
- 各算法吞吐量（MB/s）
- 与基准算法的性能比较
- **10倍性能目标达成情况** ✨

### 3. 雪崩效应分析
- 平均汉明距离
- 翻转率（目标：50%）
- 统计分析（方差、标准差、置信区间）

## 🛠️ 故障排除

### 编译错误："未找到aes_sm3_integrity.c"

```bash
# 确保路径正确，文件应位于：
../cn_test1.1/test1.1/aes_sm3_integrity.c

# 或者使用绝对路径：
gcc ... C:\Users\yuuuu\Desktop\cn_test1.1\test1.1\aes_sm3_integrity.c ...
```

### Windows上链接错误

```bash
# 确保安装了完整的MinGW工具链
# 使用-static标志静态链接：
gcc -O3 -pthread -static -o test_integrity_suite.exe ...
```

### 性能未达标

- ✅ 确认CPU支持ARMv8.2-A crypto扩展
- ✅ 关闭其他占用CPU的进程
- ✅ 使用 `-O3` 优化级别
- ✅ 在ARM平台上测试

## 📄 文件说明

| 文件 | 说明 | 大小 |
|------|------|------|
| `test_integrity_suite.c` | 完整测试套件源代码 | ~31KB |
| `generate_test_data.c` | 测试数据生成工具源代码 | ~16KB |
| `Makefile` | 自动化编译脚本（Linux/Unix） | ~5KB |
| `README.md` | 本说明文档 | ~10KB |

## 📞 技术支持

- **版本**: v1.0
- **日期**: 2025-10-22
- **作者**: 完整性校验系统开发团队

## 📜 许可证

本测试套件与完整性校验系统主程序共享相同许可证。

---

**祝测试顺利！** 🎉

