# ============================================================================
# 完整性校验系统测试 Makefile
# ============================================================================

# 编译器设置
CC = gcc
CFLAGS = -march=armv8.2-a+crypto -O3 -Wall -Wextra
LDFLAGS = -pthread -lm

# 目标平台检测
UNAME_M := $(shell uname -m)
ifneq ($(filter aarch64 arm64,$(UNAME_M)),)
    TARGET_ARCH = ARM64
else
    $(warning 警告: 当前平台不是ARM64，某些硬件加速功能可能无法使用)
    TARGET_ARCH = OTHER
endif

# 源文件 - 指向上级目录的aes_sm3_integrity.c
SRC_INTEGRITY = ../cn_test1.1/test1.1/aes_sm3_integrity.c
SRC_TEST_SUITE = test_integrity_suite.c
SRC_GEN_DATA = generate_test_data.c

# 目标文件
TARGET_TEST_SUITE = test_integrity_suite
TARGET_GEN_DATA = generate_test_data

# 测试数据目录
TEST_DATA_DIR = test_data

# 默认目标
.PHONY: all
all: info $(TARGET_TEST_SUITE) $(TARGET_GEN_DATA) test-data
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "编译完成！"
	@echo "═══════════════════════════════════════════════════════════"
	@echo ""
	@echo "下一步："
	@echo "  1. 快速测试: make test-quick"
	@echo "  2. 完整测试: make test-all"
	@echo "  3. 性能测试: make test-performance"
	@echo "  4. 雪崩测试: make test-avalanche"
	@echo ""

# 显示平台信息
.PHONY: info
info:
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════╗"
	@echo "║       完整性校验系统测试编译                              ║"
	@echo "╚══════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "平台信息:"
	@echo "  架构: $(TARGET_ARCH) ($(UNAME_M))"
	@echo "  编译器: $(CC)"
	@echo "  编译选项: $(CFLAGS)"
	@echo ""

# 编译测试套件
$(TARGET_TEST_SUITE): $(SRC_TEST_SUITE) $(SRC_INTEGRITY)
	@echo "编译测试套件..."
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ 已生成: $(TARGET_TEST_SUITE)"

# 编译测试数据生成器
$(TARGET_GEN_DATA): $(SRC_GEN_DATA)
	@echo "编译测试数据生成器..."
	$(CC) -O2 -o $@ $< -lm
	@echo "✓ 已生成: $(TARGET_GEN_DATA)"

# 生成测试数据
.PHONY: test-data
test-data: $(TARGET_GEN_DATA)
	@if [ ! -d "$(TEST_DATA_DIR)" ] || [ -z "$$(ls -A $(TEST_DATA_DIR) 2>/dev/null)" ]; then \
		echo ""; \
		echo "生成测试数据..."; \
		./$(TARGET_GEN_DATA) $(TEST_DATA_DIR); \
	else \
		echo ""; \
		echo "测试数据已存在，跳过生成"; \
		echo "如需重新生成，请运行: make clean-data && make test-data"; \
	fi

# 运行测试
.PHONY: test-quick
test-quick: $(TARGET_TEST_SUITE)
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "运行快速测试（仅正确性验证）..."
	@echo "═══════════════════════════════════════════════════════════"
	@echo ""
	./$(TARGET_TEST_SUITE) --quick

.PHONY: test-all
test-all: $(TARGET_TEST_SUITE)
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "运行完整测试套件..."
	@echo "═══════════════════════════════════════════════════════════"
	@echo ""
	./$(TARGET_TEST_SUITE) --all

.PHONY: test-performance
test-performance: $(TARGET_TEST_SUITE)
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "运行性能测试..."
	@echo "═══════════════════════════════════════════════════════════"
	@echo ""
	./$(TARGET_TEST_SUITE) --performance

.PHONY: test-avalanche
test-avalanche: $(TARGET_TEST_SUITE)
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "运行雪崩效应测试..."
	@echo "═══════════════════════════════════════════════════════════"
	@echo ""
	./$(TARGET_TEST_SUITE) --avalanche

# 清理
.PHONY: clean
clean:
	@echo "清理编译文件..."
	rm -f $(TARGET_TEST_SUITE) $(TARGET_GEN_DATA)
	rm -f *.o
	@echo "✓ 清理完成"

.PHONY: clean-data
clean-data:
	@echo "清理测试数据..."
	rm -rf $(TEST_DATA_DIR)
	@echo "✓ 测试数据已删除"

.PHONY: clean-all
clean-all: clean clean-data
	@echo "✓ 完全清理完成"

# 帮助信息
.PHONY: help
help:
	@echo ""
	@echo "═══════════════════════════════════════════════════════════"
	@echo "完整性校验系统测试 Makefile"
	@echo "═══════════════════════════════════════════════════════════"
	@echo ""
	@echo "编译目标:"
	@echo "  make                    - 编译所有组件并生成测试数据"
	@echo "  make $(TARGET_TEST_SUITE)   - 仅编译测试套件"
	@echo "  make $(TARGET_GEN_DATA) - 仅编译数据生成器"
	@echo "  make test-data          - 生成测试数据"
	@echo ""
	@echo "测试目标:"
	@echo "  make test-quick         - 运行快速测试（约1分钟）"
	@echo "  make test-all           - 运行完整测试（约5-10分钟）"
	@echo "  make test-performance   - 运行性能测试（约3-5分钟）"
	@echo "  make test-avalanche     - 运行雪崩效应测试（约1分钟）"
	@echo ""
	@echo "清理目标:"
	@echo "  make clean              - 清理编译文件"
	@echo "  make clean-data         - 清理测试数据"
	@echo "  make clean-all          - 清理所有文件"
	@echo ""
	@echo "其他:"
	@echo "  make help               - 显示本帮助信息"
	@echo "  make info               - 显示平台信息"
	@echo ""

# 依赖关系
$(TARGET_TEST_SUITE): $(SRC_INTEGRITY)

# 默认显示帮助
.DEFAULT_GOAL := all

