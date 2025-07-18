# SyzDiversity: 多样性引导的Linux内核模糊测试

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.7%2B-green.svg)](https://python.org/)
[![Linux](https://img.shields.io/badge/Platform-Linux-yellow.svg)](https://kernel.org/)

## 项目概述

SyzDiversity 是一个增强的内核模糊测试框架，它扩展了 [syzkaller](https://github.com/google/syzkaller) 并增加了先进的种子聚类功能。该项目包含两个主要组件：

1. **SyzDiversity**: 修改版的 syzkaller，用于增强内核模糊测试
2. **cluster_code**: 基于抽象语法树(AST)的种子聚类和聚类中心识别

### 主要特性

- 🔍 **增强内核模糊测试**: 扩展 syzkaller，支持多样性感知的模糊测试
- 🌳 **基于AST的聚类**: 使用抽象语法树分析程序结构
- 📊 **高级相似性度量**: 多种归一化方法 (NTED1, NTED2, NTED3, MinMax)
- 🎯 **聚类中心检测**: 智能识别代表性种子
- ⚡ **并行处理**: 针对大规模种子分析进行优化
- 📈 **全面可视化**: 详细的聚类分析和结果展示

## 项目结构

```
SyzDiversity/
├── SyzDiversity/          # 增强版 syzkaller 模糊测试框架
│   ├── bin/              # 编译后的可执行文件
│   ├── pkg/              # 核心 syzkaller 包
│   ├── executor/         # 内核执行组件
│   ├── vm/               # 虚拟机管理
│   └── ...               # 其他 syzkaller 组件
└── cluster_code/         # 种子聚类和分析工具
    ├── 1.process_ast.py                      # AST 处理
    ├── 2.preprocess_trees.py                 # 数据预处理
    ├── 3.1compute_distance_matrix_optimized.py # 距离计算
    ├── 3.2compute_similarity_matrix.py       # 相似性矩阵生成
    ├── 4.Louvain_clustering.py              # 社区检测聚类
    └── 5.cluster_center_finder.py           # 聚类中心识别
```

## 环境要求

### 系统要求
- Linux 操作系统 (推荐 Ubuntu 20.04+)
- Go 1.19+ (用于 SyzDiversity)
- Python 3.7+ (用于 cluster_code)
- 至少 16GB 内存 (大数据集推荐 32GB+)
- 100GB+ 磁盘空间

### 依赖项

#### SyzDiversity 依赖
- Linux 内核源代码
- QEMU 虚拟化支持
- 构建工具 (make, gcc 等)

#### cluster_code 依赖
```bash
pip install numpy pandas networkx scikit-learn matplotlib seaborn
pip install python-louvain edist pickle5
```

## 安装指南

### 1. SyzDiversity 设置

#### 1.1 获取指定版本 Linux 内核

下载目标内核版本：
```bash
# 方法1：从 kernel.org 下载
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.14.tar.xz
tar -xf linux-6.14.tar.xz

# 方法2：从 GitHub 克隆
git clone https://github.com/torvalds/linux.git
cd linux
git checkout v6.14
```

#### 1.2 配置和编译 Linux 内核

1. **生成默认配置文件：**
```bash
cd linux-6.14
make defconfig
make kvm_guest.config
```

2. **编辑内核配置：**
```bash
# 编辑 .config 文件，设置必要的配置选项
vim .config
```

**必要的配置选项：**
```bash
# 代码覆盖率收集 (必须开启)
CONFIG_KCOV=y
CONFIG_KCOV_INSTRUMENT_ALL=y
CONFIG_KCOV_ENABLE_COMPARISONS=y

# 调试信息 (必须开启)
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_FS=y

# 内存错误检测
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
CONFIG_UBSAN=y

# 内存泄漏检测
CONFIG_DEBUG_KMEMLEAK=y

# 禁用地址空间布局随机化以提高模糊测试效率
# CONFIG_RANDOMIZE_BASE is not set
```

3. **更新配置并编译：**
```bash
make olddefconfig
make -j$(nproc)  # 使用所有可用CPU核心
```

4. **验证配置：**
```bash
# 检查 KCOV 是否启用
grep CONFIG_KCOV .config
grep CONFIG_DEBUG_INFO .config
```

#### 1.3 配置 SyzDiversity

创建配置文件 (例如 `fuzzing.cfg`)：
```json
{
    "target": "linux/amd64",
    "http": "127.0.0.1:56741",
    "workdir": "/path/to/syzkaller/workdir",
    "kernel_obj": "/path/to/linux-6.14",
    "image": "/path/to/vm-image/bullseye.img",
    "sshkey": "/path/to/vm-image/bullseye.id_rsa",
    "syzkaller": "/path/to/SyzDiversity/",
    "procs": 8,
    "type": "qemu",
    "vm": {
        "count": 4,
        "kernel": "/path/to/linux-6.14/arch/x86/boot/bzImage",
        "cpu": 4,
        "mem": 2048
    }
}
```

### 2. cluster_code 设置

安装 Python 依赖：
```bash
cd cluster_code
pip install -r requirements.txt  # 创建此文件并包含上述依赖项
```

## 使用方法

### 阶段1：使用 SyzDiversity 进行内核模糊测试

1. **启动模糊测试：**
```bash
cd SyzDiversity
./bin/syz-manager -config=fuzzing.cfg 2>&1 | tee output.log
```

2. **监控进度：**
- Web 界面：`http://127.0.0.1:56741`
- 日志输出：`tail -f output.log`

3. **停止模糊测试：**
- 在终端中按 `Ctrl+Z`

### 阶段2：种子聚类和分析

#### 步骤1：处理 AST 数据
```bash
cd cluster_code
python 1.process_ast.py
```
**输入：** `parent_dir/seed/AST_ER/` 目录下的 JSON 文件  
**输出：** `map_AST_ER.json`

#### 步骤2：预处理数据
```bash
python 2.preprocess_trees.py
```
**输入：** `map_AST_ER.json`  
**输出：** `trees_AST_ER.pkl`

#### 步骤3：计算距离矩阵
```bash
python 3.1compute_distance_matrix_optimized.py
```
**输入：** `trees_AST_ER.pkl`  
**输出：** `cost1000-distance_matrix_ER.dat`

#### 步骤4：生成相似性矩阵
```bash
python 3.2compute_similarity_matrix.py --method NTED1
```
**可用方法：** `minmax`, `NTED1`, `NTED2`, `NTED3`  
**输出：** `similarity_matrix_NTED1.dat`, `similarity_stats_NTED1.txt`

#### 步骤5：执行聚类
```bash
python 4.Louvain_clustering.py --graph_method knn --k 200 --resolution 1.0
```
**参数说明：**
- `--graph_method`: `knn` 或 `threshold`
- `--k`: 最近邻数量 (用于 knn 方法)
- `--threshold_value`: 相似性阈值 (用于 threshold 方法)
- `--resolution`: 聚类分辨率参数

**输出：** `louvain_cluster_labels.csv`, `louvain_cluster_results.png`

#### 步骤6：查找聚类中心
```bash
# 首先创建 ast_cache 目录并复制 AST JSON 文件
mkdir ast_cache
cp /path/to/ast/files/*.json ast_cache/

# 运行聚类中心查找器
python 5.cluster_center_finder.py louvain_cluster_labels_POC_MIXED_COST1.csv
```

**输出结构：**
```
louvain_cluster_labels_POC_MIXED_COST1/
├── processed_ast/           # 处理后的 AST 文件
├── visualizations/          # 聚类可视化图像
├── cluster_centers.csv      # 聚类中心列表
└── summary.txt             # 处理摘要
```

## 许可证

本项目基于 Apache License 2.0 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 致谢

- [syzkaller](https://github.com/google/syzkaller) 团队提供的原始模糊测试框架
- Linux 内核开发社区
- 所使用聚类算法和库的贡献者
