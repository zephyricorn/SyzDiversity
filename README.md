# SyzDiversity: Diversity-Guided Linux Kernel Fuzzing

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.7%2B-green.svg)](https://python.org/)
[![Linux](https://img.shields.io/badge/Platform-Linux-yellow.svg)](https://kernel.org/)

## Overview

SyzDiversity is an enhanced kernel fuzzing framework that extends [syzkaller](https://github.com/google/syzkaller) with advanced seed clustering capabilities. The project consists of two main components:

1. **SyzDiversity**: Modified syzkaller for enhanced kernel fuzzing
2. **cluster_code**: AST-based seed clustering and cluster center identification

### Key Features

- 🔍 **Enhanced Kernel Fuzzing**: Extended syzkaller with diversity-aware fuzzing
- 🌳 **AST-based Clustering**: Analyze program structures using Abstract Syntax Trees
- 📊 **Advanced Similarity Metrics**: Multiple normalization methods (NTED1, NTED2, NTED3, MinMax)
- 🎯 **Cluster Center Detection**: Intelligent identification of representative seeds
- ⚡ **Parallel Processing**: Optimized for large-scale seed analysis
- 📈 **Comprehensive Visualization**: Detailed clustering analysis and results

## Project Structure

```
SyzDiversity/
├── SyzDiversity/          # Enhanced syzkaller fuzzing framework
│   ├── bin/              # Compiled binaries
│   ├── pkg/              # Core syzkaller packages
│   ├── executor/         # Kernel execution components
│   ├── vm/               # Virtual machine management
│   └── ...               # Other syzkaller components
└── cluster_code/         # Seed clustering and analysis tools
    ├── 1.process_ast.py                      # AST processing
    ├── 2.preprocess_trees.py                 # Data preprocessing
    ├── 3.1compute_distance_matrix_optimized.py # Distance computation
    ├── 3.2compute_similarity_matrix.py       # Similarity matrix generation
    ├── 4.Louvain_clustering.py              # Community detection clustering
    └── 5.cluster_center_finder.py           # Cluster center identification
```

## Requirements

### System Requirements
- Linux operating system (Ubuntu 20.04+ recommended)
- Go 1.19+ (for SyzDiversity)
- Python 3.7+ (for cluster_code)
- At least 16GB RAM (32GB+ recommended for large datasets)
- 100GB+ disk space

### Dependencies

#### For SyzDiversity
- Linux kernel source code
- QEMU for virtualization
- Build tools (make, gcc, etc.)

#### For cluster_code
```bash
pip install numpy pandas networkx scikit-learn matplotlib seaborn
pip install python-louvain edist pickle5
```

## Installation

### 1. SyzDiversity Setup

#### 1.1 Download and Prepare Linux Kernel

Download the target kernel version:
```bash
# Option 1: Download from kernel.org
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.14.tar.xz
tar -xf linux-6.14.tar.xz

# Option 2: Clone from GitHub
git clone https://github.com/torvalds/linux.git
cd linux
git checkout v6.14
```

#### 1.2 Configure and Compile Kernel

1. **Generate default configuration:**
```bash
cd linux-6.14
make defconfig
make kvm_guest.config
```

2. **Edit kernel configuration:**
```bash
# Edit .config file with required settings
vim .config
```

**Essential configuration options:**
```bash
# Code coverage collection (REQUIRED)
CONFIG_KCOV=y
CONFIG_KCOV_INSTRUMENT_ALL=y
CONFIG_KCOV_ENABLE_COMPARISONS=y

# Debug information (REQUIRED)
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_FS=y

# Memory error detection
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
CONFIG_UBSAN=y

# Memory leak detection
CONFIG_DEBUG_KMEMLEAK=y

# Disable KASLR for better fuzzing efficiency
# CONFIG_RANDOMIZE_BASE is not set
```

3. **Update configuration and compile:**
```bash
make olddefconfig
make -j$(nproc)  # Use all available CPU cores
```

4. **Verify configuration:**
```bash
# Check if KCOV is enabled
grep CONFIG_KCOV .config
grep CONFIG_DEBUG_INFO .config
```

#### 1.3 Configure SyzDiversity

Create a configuration file (e.g., `fuzzing.cfg`):
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

### 2. Cluster Code Setup

Install Python dependencies:
```bash
cd cluster_code
pip install -r requirements.txt  # Create this file with the dependencies listed above
```

## Usage

### Phase 1: Kernel Fuzzing with SyzDiversity

1. **Start fuzzing:**
```bash
cd SyzDiversity
./bin/syz-manager -config=fuzzing.cfg 2>&1 | tee output.log
```

2. **Monitor progress:**
- Web interface: `http://127.0.0.1:56741`
- Log output: `tail -f output.log`

3. **Stop fuzzing:**
- Press `Ctrl+Z` in the terminal

### Phase 2: Seed Clustering and Analysis

#### Step 1: Process AST Data
```bash
cd cluster_code
python 1.process_ast.py
```
**Input:** JSON files in `parent_dir/seed/AST_ER/`  
**Output:** `map_AST_ER.json`

#### Step 2: Preprocess Data
```bash
python 2.preprocess_trees.py
```
**Input:** `map_AST_ER.json`  
**Output:** `trees_AST_ER.pkl`

#### Step 3: Compute Distance Matrix
```bash
python 3.1compute_distance_matrix_optimized.py
```
**Input:** `trees_AST_ER.pkl`  
**Output:** `cost1000-distance_matrix_ER.dat`

#### Step 4: Generate Similarity Matrix
```bash
python 3.2compute_similarity_matrix.py --method NTED1
```
**Available methods:** `minmax`, `NTED1`, `NTED2`, `NTED3`  
**Output:** `similarity_matrix_NTED1.dat`, `similarity_stats_NTED1.txt`

#### Step 5: Perform Clustering
```bash
python 4.Louvain_clustering.py --graph_method knn --k 200 --resolution 1.0
```
**Parameters:**
- `--graph_method`: `knn` or `threshold`
- `--k`: Number of nearest neighbors (for knn method)
- `--threshold_value`: Similarity threshold (for threshold method)
- `--resolution`: Clustering resolution parameter

**Output:** `louvain_cluster_labels.csv`, `louvain_cluster_results.png`

#### Step 6: Find Cluster Centers
```bash
# First, create ast_cache directory and copy AST JSON files
mkdir ast_cache
cp /path/to/ast/files/*.json ast_cache/

# Run cluster center finder
python 5.cluster_center_finder.py louvain_cluster_labels_POC_MIXED_COST1.csv
```

**Output Structure:**
```
louvain_cluster_labels_POC_MIXED_COST1/
├── processed_ast/           # Processed AST files
├── visualizations/          # Cluster visualization images
├── cluster_centers.csv      # List of cluster centers
└── summary.txt             # Processing summary
```

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [syzkaller](https://github.com/google/syzkaller) team for the original fuzzing framework
- Linux kernel development community
- Contributors to the clustering algorithms and libraries used
