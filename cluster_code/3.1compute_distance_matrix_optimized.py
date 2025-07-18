# compute_distance_matrix_optimized.py
# Output is a memory-mapped file distance_matrix_ER.dat containing distances between all AST pairs

import os
import pickle
import itertools
from joblib import Parallel, delayed
from tqdm import tqdm
import numpy as np
import multiprocessing
import time


def get_cost(depth):
    """
    Return the corresponding edit cost based on node depth.

    Args:
    depth (int): Depth of the node.

    Returns:
    int: Edit cost.
    """
    if depth == 1:
        return 1  # Edit cost for root node
    elif depth == 2:
        return 1  # Edit cost for second level nodes
    else:
        return 1  # Edit cost for other level nodes


def compute_depth(nodes, adj):
    """
    Calculate the depth of each node in the tree.

    Args:
    nodes (list): List of nodes.
    adj (list): Adjacency list.

    Returns:
    dict: Mapping from node labels to depths.
    """
    depth = {nodes[0]: 1}  # Root node label mapped to depth 1

    def assign_depth(node_idx, current_depth):
        for child in adj[node_idx]:
            node_label = nodes[child]
            depth[node_label] = current_depth + 1
            assign_depth(child, current_depth + 1)

    assign_depth(0, 1)
    return depth


def create_custom_delta(x_depth, y_depth):
    """
    Create a custom delta function that assigns edit costs based on node depth.

    Args:
    x_depth (dict): Mapping from node labels to depths in tree x.
    y_depth (dict): Mapping from node labels to depths in tree y.

    Returns:
    function: Custom delta function.
    """

    def custom_delta(x, y):
        if x == y:
            return 0
        elif x is None:
            # Insert operation, use depth of y node
            return get_cost(y_depth.get(y, 1))
        elif y is None:
            # Delete operation, use depth of x node
            return get_cost(x_depth.get(x, 1))
        else:
            # Replace operation, use maximum depth of both nodes
            return get_cost(max(x_depth.get(x, 1), y_depth.get(y, 1)))
    return custom_delta


def load_trees_pickle(pickle_file_path):
    """
    Load tree data from pickle file.

    Args:
    pickle_file_path (str): Path to the pickle file.

    Returns:
    list: Tree data list arranged in index order.
    """
    with open(pickle_file_path, "rb") as f:
        trees_list = pickle.load(f)
    return trees_list


def compute_distance(pair, trees, depth_maps):
    """
    Calculate TED between two trees.

    Args:
    pair (tuple): Indices of two trees (i, j).
    trees (list): Tree data list arranged in index order.
    depth_maps (list): Depth mapping list arranged in index order.

    Returns:
    tuple: (i, j, distance)
    """
    try:
        from edist.ted import ted  # Import ted module in subprocess
        i, j = pair
        tree_i = trees[i]
        tree_j = trees[j]
        depth_i = depth_maps[i]
        depth_j = depth_maps[j]

        custom_delta = create_custom_delta(depth_i, depth_j)
        distance = ted(
            tree_i["nodes"], tree_i["adj"],
            tree_j["nodes"], tree_j["adj"],
            delta=custom_delta
        )
        return (i, j, distance)
    except Exception as e:
        print(f"Error computing distance for pair {pair}: {e}")
        return (i, j, -1)  # Use -1 to indicate error


def process_and_save(chunk, trees, depth_maps, mmap_path, num_trees):
    """
    Process a chunk of tree pairs, calculate their distances and save to memmap file.

    Args:
    chunk (list of tuples): A chunk of tree pairs list, each tuple contains (i, j).
    trees (list): Tree data list arranged in index order.
    depth_maps (list): Depth mapping list arranged in index order.
    mmap_path (str): memmap file path.
    num_trees (int): Number of trees, used for memmap shape.

    Returns:
    int: Number of tree pairs processed.
    """
    distances = []
    for pair in chunk:
        result = compute_distance(pair, trees, depth_maps)
        distances.append(result)

    # Open memory-mapped file
    mmap_file = np.memmap(mmap_path, dtype='float32', mode='r+', shape=(num_trees, num_trees))
    for i, j, distance in distances:
        mmap_file[i, j] = distance
        mmap_file[j, i] = distance  # Symmetric matrix
    del mmap_file  # Release memory-mapped file
    return len(distances)


def chunked_combinations(iterable, n):
    """
    Generator function that generates combination pairs in chunks.

    Args:
    iterable: Iterable object.
    n (int): Size of each chunk.

    Yields:
    list: Combination pairs in each chunk.
    """
    it = iter(iterable)
    while True:
        chunk = list(itertools.islice(it, n))
        if not chunk:
            break
        yield chunk


def main():
    pickle_file = "trees_AST_POC_MIXED.pkl"  # Preprocessed pickle file
    mmap_file_path = "cost1-distance_matrix_POC_MIXED.dat"  # Memory-mapped file path
    n_jobs = min(multiprocessing.cpu_count(), 90)  # Ensure not exceeding physical cores, use all available CPU cores
    chunk_size = 600000  # Number of tree pairs processed per chunk

    # Start timing
    start_time = time.perf_counter()

    # Check if pickle file exists
    if not os.path.isfile(pickle_file):
        print(f"File '{pickle_file}' does not exist. Please run preprocessing script 'preprocess_trees.py' first.")
        return

    # Load tree data
    print("Loading tree data...")
    trees = load_trees_pickle(pickle_file)
    num_trees = len(trees)
    print(f"Loaded {num_trees} AST trees.")

    # Pre-compute all depth mappings
    print("Computing node depth mappings for all trees...")
    depth_maps = []
    for idx in tqdm(range(num_trees), desc="Computing depth mappings"):
        tree = trees[idx]
        nodes = tree["nodes"]
        adj = tree["adj"]
        depth = compute_depth(nodes, adj)
        depth_maps.append(depth)
    print("Node depth mapping computation completed.")

    # Create memory-mapped file
    print("Creating memory-mapped file...")
    distance_matrix = np.memmap(mmap_file_path, dtype='float32', mode='w+', shape=(num_trees, num_trees))
    distance_matrix[:, :] = 0  # Initialize to 0
    distance_matrix.flush()
    del distance_matrix  # Release memory-mapped file
    print(f"Memory-mapped file '{mmap_file_path}' created successfully.")

    # Generate all tree pairs
    print("Generating all tree pairs...")
    tree_indices = list(range(num_trees))
    tree_pairs = itertools.combinations(tree_indices, 2)
    total_pairs = num_trees * (num_trees - 1) // 2
    print(f"Total {total_pairs} tree pairs need distance calculation.")

    # Process tree pairs in chunks using generator
    print("Processing tree pairs in chunks...")

    # Define parallel processing function
    def parallel_process_and_save(chunk):
        return process_and_save(chunk, trees, depth_maps, mmap_file_path, num_trees)

    # Calculate total chunks
    total_chunks = (total_pairs + chunk_size - 1) // chunk_size

    # Use Joblib for parallel processing, avoid generating all chunks at once
    print("Starting parallel computation of tree edit distances...")
    with Parallel(n_jobs=n_jobs, backend='loky') as parallel:
        results = parallel(
            delayed(parallel_process_and_save)(chunk)
            for chunk in tqdm(chunked_combinations(tree_pairs, chunk_size), total=total_chunks, desc="Computing progress")
        )

    print(f"Tree edit distances for all tree pairs have been saved to '{mmap_file_path}'.")

    # End timing
    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    print(f"\nProgram runtime: {elapsed_time:.2f} seconds")
    print("All tasks completed.")


if __name__ == "__main__":
    main()
