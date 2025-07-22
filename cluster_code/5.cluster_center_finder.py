#!/usr/bin/env python3
import os
import sys
import csv
import json
import numpy as np
import shutil
from collections import defaultdict
import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Set matplotlib backend to non-interactive
import matplotlib.pyplot as plt
from tqdm import tqdm
import multiprocessing
from functools import partial
from itertools import combinations

# Try to import edist library, provide alternative if not available
try:
    from edist.ted import ted

    EDIST_AVAILABLE = True
except ImportError:
    EDIST_AVAILABLE = False
    print("Warning: edist library not installed, will use alternative distance calculation method.")
    print("To use precise tree edit distance, please run: pip install edist")

# ==========================================================
# Configuration Section - Can be modified as needed
# ==========================================================
WORKDIR = "/home/qjj/python_projects/ted_cluster"
CSV_FILENAME = "louvain_cluster_labels_POC_MIXED_COST1.csv"
MIN_CLUSTER_SIZE = 5  # Minimum cluster size threshold
VISUALIZATION = True  # Whether to generate visualization
# Use CPU cores - 2, reserve some system resources, ensure at least 1
NUM_PROCESSES = max(1, multiprocessing.cpu_count() - 2)

print(f"Configured to use {NUM_PROCESSES} CPU cores for parallel computation")

# ==========================================================
# Automatically build paths
# ==========================================================
CLUSTER_INFO_PATH = os.path.join(WORKDIR, CSV_FILENAME)
RESULT_DIR_NAME = os.path.splitext(CSV_FILENAME)[0]  # Use CSV filename (without extension) as result directory
RESULT_DIR = os.path.join(WORKDIR, RESULT_DIR_NAME)

# Output directory structure
RAW_AST_DIR = os.path.join(WORKDIR, "ast_cache")  # Raw AST directory
PROCESSED_AST_DIR = os.path.join(RESULT_DIR, "processed_ast")  # Processed AST directory
VIZ_DIR = os.path.join(RESULT_DIR, "visualizations")  # Visualization output directory
OUTPUT_CORE_PATH = os.path.join(RESULT_DIR, "cluster_centers_COST20.csv")  # Output cluster center file


# ==========================================================
# AST Processing Functions
# ==========================================================
def traverse_args(args, nodes, adj, parent_index):
    """Recursively traverse arguments and their sub-arguments to build nodes and adjacency lists"""
    children = []
    for arg in args:
        arg_type = arg.get("type", "UnknownType")
        arg_value = arg.get("value", "")
        if isinstance(arg_value, int):
            arg_label = f"{arg_type}: {arg_value}"
        elif isinstance(arg_value, str) and arg_type != "*prog.GroupArg":
            arg_label = f"{arg_type}: {arg_value}"
        else:
            arg_label = f"{arg_type}"

        nodes.append(arg_label)
        adj.append([])
        current_index = len(nodes) - 1
        children.append(current_index)

        sub_args = arg.get("sub_args", [])
        if sub_args:
            traverse_args(sub_args, nodes, adj, current_index)

    adj[parent_index].extend(children)


def process_program_ast(program_ast):
    """Process a single ProgramAST JSON object to generate nodes and adjacency lists"""
    nodes = ["ProgramAST"]
    adj = [[]]

    calls = program_ast.get("calls", [])
    for call in calls:
        call_name = call.get("name", "UnnamedCall")
        nodes.append(call_name)
        adj.append([])
        call_index = len(nodes) - 1
        adj[0].append(call_index)

        args = call.get("args", [])
        traverse_args(args, nodes, adj, call_index)

    return nodes, adj


# Top-level worker function for parallel processing of AST files
def _process_single_ast_worker(prog_hash, current_raw_ast_dir, current_processed_ast_dir):
    """
    Worker function for parallel processing of a single AST file.
    prog_hash: Hash value of the program.
    current_raw_ast_dir: Directory where raw AST files are located.
    current_processed_ast_dir: Directory where processed AST files are saved.
    """
    raw_ast_path = os.path.join(current_raw_ast_dir, f"{prog_hash}.json")
    processed_ast_path = os.path.join(current_processed_ast_dir, f"{prog_hash}.json")

    if not os.path.exists(raw_ast_path):
        return "missing"

    try:
        with open(raw_ast_path, 'r') as f:
            program_ast = json.load(f)

        nodes, adj = process_program_ast(program_ast)
        processed_ast = {"nodes": nodes, "adj": adj}

        with open(processed_ast_path, 'w') as f:
            json.dump(processed_ast, f, indent=2)
        return "success"
    except Exception as e:
        return f"error: {prog_hash} - {str(e)}"


def process_ast_files_parallel(cluster_info_path, raw_ast_dir, processed_ast_dir):
    """Process all AST files in parallel, generating new files with nodes and adj fields"""
    if not os.path.exists(processed_ast_dir):
        os.makedirs(processed_ast_dir)

    program_hashes = []
    with open(cluster_info_path, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        for row in reader:
            if len(row) >= 1:
                program_hashes.append(row[0])

    print(f"Found {len(program_hashes)} programs in cluster info file")

    worker_function = partial(_process_single_ast_worker,
                              current_raw_ast_dir=raw_ast_dir,
                              current_processed_ast_dir=processed_ast_dir)

    print("Processing AST files in parallel...")
    results = []
    with multiprocessing.Pool(processes=NUM_PROCESSES) as pool:
        results = list(tqdm(pool.imap(worker_function, program_hashes), total=len(program_hashes)))

    success_count = results.count("success")
    missing_count = results.count("missing")
    error_results = [r for r in results if r not in ["success", "missing"]]
    error_count = len(error_results)

    print(f"AST processing completed: {success_count} successful, {missing_count} missing, {error_count} errors")
    if error_count > 0:
        print("Programs with errors (showing up to first 10):")
        for err_msg in error_results[:10]:
            print(f"  - {err_msg}")
        if error_count > 10:
            print(f"  ... and {error_count - 10} other errors not shown")
    return success_count > 0


# ==========================================================
# Tree Edit Distance Calculation Functions - Using edist library
# ==========================================================
def get_cost(depth):
    """Return corresponding edit cost based on node depth"""
    return 1  # Use uniform edit cost


def compute_depth(nodes, adj):
    """Calculate the depth of each node in the tree"""
    if not nodes:  # Handle case of empty node list
        return {}
    depth_map = {}  # Use dictionary to store node index to depth mapping

    # Initialize depth of root node (index 0)
    # Ensure adj has at least one element corresponding to root node
    if adj:
        depth_map[0] = 1

        # Use queue for breadth-first search (BFS) to assign depths
        queue = [(0, 1)]  # (node_index, current_depth)

        visited_indices = {0}

        head = 0
        while head < len(queue):
            node_idx, current_d = queue[head]
            head += 1

            # Ensure adj[node_idx] is valid
            if node_idx < len(adj):
                for child_idx in adj[node_idx]:
                    if child_idx not in visited_indices and child_idx < len(nodes):  # Ensure child node index is valid
                        depth_map[child_idx] = current_d + 1
                        visited_indices.add(child_idx)
                        queue.append((child_idx, current_d + 1))
            else:
                # print(f"Warning: Node index {node_idx} in compute_depth exceeds adjacency list range.")
                pass

    # Convert index-based depth mapping to node label-based depth mapping (if needed, but edist might use indices directly)
    # For compatibility with original create_custom_delta, we return label-based depths
    # Note: If node labels are not unique, there might be issues here. Assume they are unique within a single AST, or take the first occurrence.
    # A more robust approach would be to have create_custom_delta directly use index-based depths.
    # But to minimize changes, we keep it as is for now, but need to be aware of this potential issue.
    node_label_depth = {}
    for idx, d in depth_map.items():
        if idx < len(nodes):
            node_label_depth[nodes[idx]] = d
        # else:
        # print(f"Warning: Index {idx} exceeds node list range when converting labels in compute_depth.")

    # Ensure root node label is in mapping
    if nodes and nodes[0] not in node_label_depth and 0 in depth_map:
        node_label_depth[nodes[0]] = depth_map[0]

    return node_label_depth


def create_custom_delta(x_depth_labels, y_depth_labels):
    """Create a custom delta function that assigns edit costs based on node depth"""

    def custom_delta(x_label, y_label):  # x, y are node labels
        if x_label == y_label:
            return 0

        cost = 1  # Default cost
        if x_label is None:  # Insert y_label
            cost = get_cost(y_depth_labels.get(y_label, 1))
        elif y_label is None:  # Delete x_label
            cost = get_cost(x_depth_labels.get(x_label, 1))
        else:  # Replace x_label with y_label
            cost_x = x_depth_labels.get(x_label, 1)
            cost_y = y_depth_labels.get(y_label, 1)
            cost = get_cost(max(cost_x, cost_y))
        return cost

    return custom_delta


def load_ast_from_file(ast_path):
    """Load AST file"""
    try:
        with open(ast_path, 'r') as f:
            ast_data = json.load(f)

        if "nodes" not in ast_data or "adj" not in ast_data:
            return None
        nodes = ast_data.get('nodes', [])
        adj_list = ast_data.get('adj', [])
        if not nodes or not adj_list:  # Ensure nodes and adj_list are not empty, and adj_list length matches nodes
            # Further check if adj_list structure is reasonable
            if len(adj_list) != len(nodes):
                # print(f"Warning: AST file {ast_path} 'nodes' and 'adj' length mismatch.")
                return None
            for i, children in enumerate(adj_list):
                if not isinstance(children, list):  # Each adjacency list item should be a list
                    # print(f"Warning: AST file {ast_path} 'adj' format incorrect (item {i} is not a list).")
                    return None
                for child_idx in children:
                    if not isinstance(child_idx, int) or child_idx < 0 or child_idx >= len(nodes):
                        # print(f"Warning: AST file {ast_path} 'adj' contains invalid child node index {child_idx} (parent node {i}).")
                        return None
            return None  # If only empty nodes or empty adjacency list, also return None

        return ast_data
    except json.JSONDecodeError:
        # print(f"Warning: AST file {ast_path} JSON parsing failed.")
        return None
    except Exception:
        # print(f"Warning: Unknown error occurred while loading AST file {ast_path}.")
        return None


def simple_tree_distance(ast1, ast2):
    """Simple tree distance calculation for fallback"""
    if not ast1 or not ast2:
        return float('inf')
    nodes1 = set(ast1.get('nodes', []))
    nodes2 = set(ast2.get('nodes', []))
    if not nodes1 and not nodes2:
        return 0.0
    if not nodes1 or not nodes2:  # If one is empty while the other is not
        return float('inf')  # Or a large penalty value

    intersection = len(nodes1.intersection(nodes2))
    union = len(nodes1.union(nodes2))
    if union == 0:  # Avoid division by zero, although the case where both are empty has been handled above
        return 0.0

    jaccard = 1.0 - (intersection / union)
    size_diff = abs(len(ast1.get('nodes', [])) - len(ast2.get('nodes', [])))
    return jaccard + 0.01 * size_diff


def compute_ted_distance(ast1, ast2):
    """Calculate tree edit distance between two ASTs"""
    if not ast1 or not ast2:
        return float('inf')

    try:
        if EDIST_AVAILABLE:
            # edist library expects adj to be an adjacency list where each inner list contains child node indices
            # nodes is a list of node labels
            # Ensure ast1 and ast2's nodes and adj are valid
            if not ast1.get('nodes') or not ast1.get('adj') or \
                    not ast2.get('nodes') or not ast2.get('adj'):
                # print("Warning: compute_ted_distance received invalid AST structure (missing nodes/adj).")
                return simple_tree_distance(ast1, ast2)  # Fallback

            depth1_labels = compute_depth(ast1['nodes'], ast1['adj'])
            depth2_labels = compute_depth(ast2['nodes'], ast2['adj'])

            custom_delta_func = create_custom_delta(depth1_labels, depth2_labels)

            distance = ted(
                ast1['nodes'], ast1['adj'],
                ast2['nodes'], ast2['adj'],
                delta=custom_delta_func
            )
            return distance
        else:
            return simple_tree_distance(ast1, ast2)
    except Exception as e:
        # print(f"Error computing TED: {e}. Using simple distance as fallback. AST1: {ast1.get('nodes', [])[:5]}, AST2: {ast2.get('nodes', [])[:5]}")
        return simple_tree_distance(ast1, ast2)


def calculate_distance_pair(pair_with_asts):
    """Calculate distance between a pair of ASTs"""
    i, j, ast1, ast2 = pair_with_asts
    dist = compute_ted_distance(ast1, ast2)
    return i, j, dist


# ==========================================================
# Cluster center finding functionality - parallel version
# ==========================================================
def find_cluster_centers_parallel(cluster_info_path, ast_dir, min_cluster_size=5, viz_dir=None):
    """Find cluster centers in parallel for each cluster"""
    print(f"Reading cluster information from {cluster_info_path}")
    clusters = defaultdict(list)
    total_programs = 0
    with open(cluster_info_path, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        for row in reader:
            if len(row) >= 2:
                try:
                    program_hash, cluster_id_str = row[0], row[1]
                    cluster_id = int(cluster_id_str)
                    clusters[cluster_id].append(program_hash)
                    total_programs += 1
                except ValueError:
                    print(f"Warning: Unable to convert cluster ID '{cluster_id_str}' to integer. Skipping row: {row}")
                    continue

    print(f"Found {len(clusters)} clusters with total {total_programs} programs")
    large_clusters = {cid: progs for cid, progs in clusters.items() if len(progs) >= min_cluster_size}
    print(f"{len(large_clusters)} clusters have size at least {min_cluster_size}")

    centers = {}
    for cluster_id, program_hashes in tqdm(large_clusters.items(), desc="Processing clusters"):
        print(f"\nProcessing cluster {cluster_id} with {len(program_hashes)} programs")
        asts = {}
        valid_hashes = []
        for prog_hash in program_hashes:
            ast_path = os.path.join(ast_dir, f"{prog_hash}.json")
            if os.path.exists(ast_path):
                ast = load_ast_from_file(ast_path)
                if ast:
                    asts[prog_hash] = ast
                    valid_hashes.append(prog_hash)
            # else:
            # print(f"Warning: AST file not found for cluster {cluster_id}: {ast_path}")

        if len(asts) < 1:  # If there's not even one valid AST
            print(f"Cluster {cluster_id}: Cannot find any valid AST. Unable to determine center.")
            if program_hashes:  # Still try to select one as fallback, even if its AST is invalid
                centers[cluster_id] = program_hashes[0]
                print(f"Will use first program {program_hashes[0]} as nominal center for cluster {cluster_id} (AST may be invalid).")
            continue

        if len(asts) < 2:  # If there's only one valid AST
            center_hash = valid_hashes[0]
            centers[cluster_id] = center_hash
            print(f"Cluster {cluster_id}: Only one valid AST ({center_hash}), setting it as center.")
            if viz_dir:
                G = nx.Graph()
                G.add_node(center_hash, is_center=True)
                plt.figure(figsize=(8, 8))
                pos = {center_hash: (0, 0)}
                nx.draw_networkx_nodes(G, pos, node_size=200, node_color='red', alpha=0.8)
                labels = {center_hash: center_hash[:8]}
                nx.draw_networkx_labels(G, pos, labels, font_size=10, font_weight='bold')
                plt.title(f"Cluster {cluster_id} (Single Valid Program)\nCenter: {center_hash[:8]}")
                plt.axis('off')
                viz_path = os.path.join(viz_dir, f"cluster_{cluster_id}.png")
                plt.savefig(viz_path, dpi=300, bbox_inches='tight')
                plt.close()
                print(f"Single node cluster visualization saved to {viz_path}")
            continue

        print(f"Loaded {len(asts)} valid ASTs from {len(valid_hashes)} hashes.")

        prog_list = valid_hashes  # Use valid hash list
        n = len(prog_list)
        distances = np.full((n, n), float('inf'))  # Initialize to infinity
        np.fill_diagonal(distances, 0)  # Distance to self is 0

        pairs = []
        for i in range(n):
            for j in range(i + 1, n):
                pairs.append((i, j, asts[prog_list[i]], asts[prog_list[j]]))

        if not pairs:
            print(f"Cluster {cluster_id}: No AST pairs for distance calculation (valid AST count: {n}).")
            if prog_list:  # If there's at least one valid AST
                centers[cluster_id] = prog_list[0]
                print(f"Will use first valid AST {prog_list[0]} as center for cluster {cluster_id}.")
            elif program_hashes:  # If no valid AST but have original hashes
                centers[cluster_id] = program_hashes[0]
                print(f"Will use first program {program_hashes[0]} as nominal center for cluster {cluster_id} (AST may be invalid).")
            continue

        print(f"Computing TED distances for cluster {cluster_id} in parallel ({len(pairs)} pairs)")
        with multiprocessing.Pool(processes=NUM_PROCESSES) as pool:
            results = list(
                tqdm(pool.imap(calculate_distance_pair, pairs), total=len(pairs), desc=f"Computing cluster {cluster_id} distances",
                     leave=False))

        for i, j, dist in results:
            distances[i, j] = dist
            distances[j, i] = dist

        # Check if any distance calculation succeeded
        if np.all(np.isinf(distances[np.triu_indices(n, k=1)])):  # If all off-diagonal elements are inf
            print(f"Warning: All AST pairs in cluster {cluster_id} have infinite distance. Cannot reliably select center.")
            centers[cluster_id] = prog_list[0]  # Select first as fallback
            print(f"Will use first valid AST {prog_list[0]} as center for cluster {cluster_id}.")
            # Can optionally generate a simple visualization for such clusters
            if viz_dir:
                G = nx.Graph()
                for i_node in range(n):
                    G.add_node(prog_list[i_node], is_center=(i_node == 0))
                plt.figure(figsize=(12, 12))
                try:
                    pos = nx.spring_layout(G, k=0.5, iterations=20, seed=42)
                except:
                    pos = nx.random_layout(G, seed=42)
                node_colors = ['red' if G.nodes[node]['is_center'] else 'lightcoral' for node in G.nodes()]
                nx.draw_networkx_nodes(G, pos, node_size=100, node_color=node_colors, alpha=0.8)
                labels = {prog_list[i_node]: prog_list[i_node][:8] for i_node in range(n) if i_node == 0}
                nx.draw_networkx_labels(G, pos, labels, font_size=8, font_weight='bold')
                plt.title(f"Cluster {cluster_id} (All distances inf)\nCenter: {prog_list[0][:8]}")
                plt.axis('off')
                viz_path = os.path.join(viz_dir, f"cluster_{cluster_id}_inf_distances.png")
                plt.savefig(viz_path, dpi=300, bbox_inches='tight')
                plt.close()
                print(f"Saved visualization for cluster {cluster_id} (all distances inf) to {viz_path}")
            continue

        avg_distances = np.nansum(np.where(np.isinf(distances), np.nan, distances), axis=1) / (n - 1)

        # If all average distances are NaN or Inf (e.g., only one node, or all distances are inf)
        if np.all(np.isnan(avg_distances)) or np.all(np.isinf(avg_distances)):
            center_idx = 0  # Default to first one
        else:
            center_idx = np.nanargmin(avg_distances)

        center_hash = prog_list[center_idx]
        min_avg_dist = avg_distances[center_idx] if not np.isnan(avg_distances[center_idx]) else float('inf')

        print(f"Cluster {cluster_id} center: {center_hash} (average distance: {min_avg_dist:.2f})")
        centers[cluster_id] = center_hash

        if viz_dir:
            G = nx.Graph()
            for i in range(n):
                G.add_node(prog_list[i], is_center=(i == center_idx))

            finite_distances = distances[np.triu_indices(n, k=1)]
            finite_distances = finite_distances[np.isfinite(finite_distances)]

            threshold = np.mean(finite_distances) * 1.5 if finite_distances.size > 0 else float('inf')

            for i in range(n):
                for j in range(i + 1, n):
                    if distances[i, j] < threshold and distances[i, j] < float('inf'):
                        G.add_edge(prog_list[i], prog_list[j], weight=distances[i, j])

            plt.figure(figsize=(12, 12))
            if not G.nodes():
                print(f"Cluster {cluster_id}: Graph is empty, skipping visualization.")
                plt.close()
                continue

            try:
                pos = nx.spring_layout(G, k=0.5, iterations=30, seed=42)
            except Exception as e:
                # print(f"Cluster {cluster_id}: Unable to generate spring layout ({e}), using random layout.")
                pos = nx.random_layout(G, seed=42)

            node_colors = ['red' if G.nodes[node].get('is_center', False) else 'skyblue' for node in G.nodes()]
            nx.draw_networkx_nodes(G, pos, node_size=100, node_color=node_colors, alpha=0.8)

            if G.edges():
                # edge_weights = [G[u][v].get('weight', 1.0) for u, v in G.edges()] # No longer needed since we don't draw by weight
                nx.draw_networkx_edges(G, pos, width=1, alpha=0.5, edge_color='gray')

            labels_viz = {prog_list[i]: prog_list[i][:8] if i == center_idx else "" for i in range(n)}
            nx.draw_networkx_labels(G, pos, labels_viz, font_size=8, font_weight='bold')

            plt.title(f"Cluster {cluster_id} contains {n} programs\nCenter: {center_hash[:8]}")
            plt.axis('off')
            viz_path = os.path.join(viz_dir, f"cluster_{cluster_id}.png")
            plt.savefig(viz_path, dpi=300, bbox_inches='tight')
            plt.close()
            print(f"Visualization saved to {viz_path}")
    return centers


def save_cluster_centers(centers, output_path):
    """Save cluster centers to CSV file"""
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['ClusterID', 'SeedHash'])
        for cluster_id, center_hash in sorted(centers.items()):  # Save sorted by ID
            writer.writerow([cluster_id, center_hash])
    print(f"Saved {len(centers)} cluster centers to {output_path}")


# ==========================================================
# Main program
# ==========================================================
def main():
    print("=" * 60)
    print("Cluster Center Finder - Parallel Solution")
    print("=" * 60)
    print(f"Working directory: {WORKDIR}")
    print(f"Cluster info file: {CLUSTER_INFO_PATH}")
    print(f"Result directory: {RESULT_DIR}")
    print(f"Raw AST directory: {RAW_AST_DIR}")
    print(f"Processed AST directory: {PROCESSED_AST_DIR}")
    print(f"Minimum cluster size: {MIN_CLUSTER_SIZE}")
    print(f"Parallel processes: {NUM_PROCESSES}")
    print("=" * 60)

    if not os.path.exists(CLUSTER_INFO_PATH):
        print(f"Error: Cannot find cluster info file: {CLUSTER_INFO_PATH}")
        return 1
    if not os.path.exists(RAW_AST_DIR):
        print(f"Error: Cannot find raw AST directory: {RAW_AST_DIR}")
        return 1

    if not os.path.exists(RESULT_DIR):
        os.makedirs(RESULT_DIR)
        print(f"Created result directory: {RESULT_DIR}")
    if VISUALIZATION and not os.path.exists(VIZ_DIR):
        os.makedirs(VIZ_DIR)
        print(f"Created visualization directory: {VIZ_DIR}")

    print("\nStep 1: Process AST files in parallel")
    if not process_ast_files_parallel(CLUSTER_INFO_PATH, RAW_AST_DIR, PROCESSED_AST_DIR):
        print("Error: AST processing failed or no files were successfully processed, cannot continue. Please check error logs.")
        return 1

    print("\nStep 2: Find cluster centers in parallel")
    viz_dir_param = VIZ_DIR if VISUALIZATION else None
    centers = find_cluster_centers_parallel(CLUSTER_INFO_PATH, PROCESSED_AST_DIR, MIN_CLUSTER_SIZE, viz_dir_param)

    print("\nStep 3: Save results")
    save_cluster_centers(centers, OUTPUT_CORE_PATH)

    summary_path = os.path.join(RESULT_DIR, "summary.txt")
    processed_ast_count = 0
    if os.path.exists(PROCESSED_AST_DIR):
        processed_ast_count = len([name for name in os.listdir(PROCESSED_AST_DIR)
                                   if name.endswith('.json') and os.path.isfile(os.path.join(PROCESSED_AST_DIR, name))])

    with open(summary_path, 'w') as f:
        f.write("Cluster Center Finding Summary\n")
        f.write("=" * 40 + "\n")
        f.write(f"Source cluster info file: {CSV_FILENAME}\n")
        f.write(f"Processed and saved AST count: {processed_ast_count}\n")
        f.write(f"Found cluster center count: {len(centers)}\n")
        f.write(f"Minimum cluster size threshold: {MIN_CLUSTER_SIZE}\n")
        f.write(f"CPU cores used: {NUM_PROCESSES}\n")
        f.write("\nCluster center list (sorted by cluster ID):\n")
        for cid, center_hash in sorted(centers.items()):
            f.write(f"  Cluster {cid}: {center_hash}\n")

            print(f"Generated summary file: {summary_path}")
    print("\nProcessing completed!")
    print(f"All results saved to: {RESULT_DIR}")
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()  # Ensure proper operation in packaged or non-fork environments
    sys.exit(main())