#!/bin/bash
# AES-SM3完整性校验算法 - 测试编译脚本
# 自动处理main函数冲突问题

set -e

echo "════════════════════════════════════════════════════════"
echo "  AES-SM3完整性校验算法 - 测试编译和运行"
echo "════════════════════════════════════════════════════════"
echo ""

# 检查必要文件
if [ ! -f "aes_sm3_integrity.c" ]; then
    echo "错误: 找不到 aes_sm3_integrity.c"
    exit 1
fi

if [ ! -f "test_aes_sm3_integrity.c" ]; then
    echo "错误: 找不到 test_aes_sm3_integrity.c"
    exit 1
fi

# 检查CPU架构
ARCH=$(uname -m)
echo "检测到CPU架构: $ARCH"

# 设置编译选项
if [[ "$ARCH" =~ "aarch64" || "$ARCH" =~ "arm" ]]; then
    echo "使用ARM优化编译选项"
    COMPILE_FLAGS="-march=armv8.2-a+crypto -O3 -funroll-loops -ftree-vectorize -finline-functions -ffast-math -flto -fomit-frame-pointer -pthread"
    FALLBACK_FLAGS="-march=armv8-a+crypto -O3 -funroll-loops -ftree-vectorize -finline-functions -pthread"
else
    echo "警告: 非ARM架构，性能可能不佳"
    COMPILE_FLAGS="-O3 -funroll-loops -ftree-vectorize -finline-functions -pthread"
    FALLBACK_FLAGS="$COMPILE_FLAGS"
fi

echo ""
echo "步骤1: 创建库文件（不含main函数）..."

# 创建不含main函数的库文件
# 找到main函数的起始行（通常在最后）
MAIN_LINE=$(grep -n "^int main()" aes_sm3_integrity.c | tail -1 | cut -d: -f1)

if [ -z "$MAIN_LINE" ]; then
    # 如果没找到，尝试查找带空格的main
    MAIN_LINE=$(grep -n "int main\s*()" aes_sm3_integrity.c | tail -1 | cut -d: -f1)
fi

if [ -z "$MAIN_LINE" ]; then
    echo "警告: 无法找到main函数，使用默认行数3413"
    MAIN_LINE=3413
fi

# 减1行，确保不包含main函数行
MAIN_LINE=$((MAIN_LINE - 1))
echo "提取前 $MAIN_LINE 行代码..."

head -n $MAIN_LINE aes_sm3_integrity.c > aes_sm3_integrity_lib.c

echo "✓ 库文件创建成功"
echo ""

echo "步骤2: 编译测试程序..."

# 尝试编译
if gcc $COMPILE_FLAGS -o test_aes_sm3 aes_sm3_integrity_lib.c test_aes_sm3_integrity.c -lm 2>compile_error.log; then
    echo "✓ 编译成功！"
    rm -f compile_error.log
else
    echo "⚠ 使用默认编译选项失败，尝试备选方案..."
    
    if gcc $FALLBACK_FLAGS -o test_aes_sm3 aes_sm3_integrity_lib.c test_aes_sm3_integrity.c -lm 2>compile_error.log; then
        echo "✓ 使用备选编译选项成功！"
        rm -f compile_error.log
    else
        echo "✗ 编译失败"
        echo ""
        echo "错误信息:"
        cat compile_error.log
        rm -f compile_error.log
        rm -f aes_sm3_integrity_lib.c
        exit 1
    fi
fi

echo ""
echo "步骤3: 运行测试..."
echo "════════════════════════════════════════════════════════"
echo ""

./test_aes_sm3

EXIT_CODE=$?

echo ""
echo "════════════════════════════════════════════════════════"
echo "  清理临时文件..."
echo "════════════════════════════════════════════════════════"
rm -f aes_sm3_integrity_lib.c

if [ $EXIT_CODE -eq 0 ]; then
    echo "✓ 测试完成！"
else
    echo "✗ 测试失败，退出码: $EXIT_CODE"
    exit $EXIT_CODE
fi

echo ""
echo "测试可执行文件: ./test_aes_sm3"
echo "可以直接运行: ./test_aes_sm3"
echo ""

