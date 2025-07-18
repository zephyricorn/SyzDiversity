# compute_similarity_matrix.py

import os
import argparse
import pickle
import numpy as np
from tqdm import tqdm


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


def get_node_counts(trees_list):
    """
    Get the number of nodes for each tree.

    Args:
        trees_list (list): Tree data list, each element is a dictionary containing 'nodes' and 'adj'.

    Returns:
        list: List of node counts for each tree.
    """
    return [len(tree["nodes"]) for tree in trees_list]


import numpy as np
from tqdm import tqdm


def normalize_ted_matrix(ted_matrix, node_counts, method='minmax', a=1):
    """
    Normalize the tree edit distance matrix and compute the mean and variance of the similarity matrix.

    Args:
        ted_matrix (numpy.memmap): Memory-mapped object of tree edit distance matrix.
        node_counts (list): List of node counts for each tree.
        method (str): Normalization method, 'minmax', 'NTED1', 'NTED2', or 'NTED3'.
        a (int): Parameter a in normalization method 3, default value is 1000.

    Returns:
        tuple: Contains memory-mapped object of normalized similarity matrix, mean, and variance.
    """
    num_trees = len(node_counts)
    similarity_matrix_path = f"similarity_matrix_{method}.dat"
    similarity_matrix = np.memmap(similarity_matrix_path, dtype='float32', mode='w+', shape=(num_trees, num_trees))

    print(f"Normalization method: {method}")
    print(f"Similarity matrix will be saved as '{similarity_matrix_path}'")

    total_sum = 0.0
    total_sum_sq = 0.0

    if method == 'minmax':
        # Calculate minimum and maximum values of upper triangular part (excluding diagonal)
        triu_indices = np.triu_indices(num_trees, k=1)
        upper_values = ted_matrix[triu_indices]
        min_val = np.min(upper_values)
        max_val = np.max(upper_values)
        print(f"Minimum value of upper triangular part: {min_val}")
        print(f"Maximum value of upper triangular part: {max_val}")

        for i in tqdm(range(num_trees), desc="Normalization progress"):
            ted_row = ted_matrix[i, :]
            # Normalize using min and max
            normalized_ted = (ted_row - min_val) / (max_val - min_val)
            # Calculate similarity
            similarity = 1 - normalized_ted
            # Ensure similarity is within [0,1] range
            similarity = np.clip(similarity, 0, 1)
            # Accumulate sum and sum of squares for upper triangular part
            if i < num_trees - 1:
                upper_part = similarity[i + 1:]
                total_sum += np.sum(upper_part)
                total_sum_sq += np.sum(upper_part ** 2)
            # Save to similarity matrix
            similarity_matrix[i, :] = similarity.astype('float32')
        total_elements = num_trees * (num_trees - 1) / 2
    else:
        # Keep original normalization methods
        for i in tqdm(range(num_trees), desc="Normalization progress"):
            ted_row = ted_matrix[i, :]

            # Get corresponding tree node counts
            n1 = node_counts[i]
            n2 = node_counts  # Column corresponds to all trees

            if method == 'NTED1':
                # NTED1: Normalized TED = TED / max(|T1|, |T2|)
                max_nodes = np.maximum(n1, n2)
                normalized_ted = ted_row / max_nodes
            elif method == 'NTED2':
                # NTED2: Normalized TED = TED / (|T1| + |T2|)
                sum_nodes = n1 + np.array(n2)
                normalized_ted = ted_row / sum_nodes
            elif method == 'NTED3':
                # NTED3: Normalized TED = (a*(|T1| + |T2|) - TED) / 2
                sum_nodes = n1 + np.array(n2)
                normalized_ted = (a * sum_nodes - ted_row) / 2
            else:
                raise ValueError(f"Unknown normalization method: {method}")

            # Calculate similarity
            similarity = 1 - normalized_ted

            # Handle possible outliers, ensure similarity is within [0,1] range
            similarity = np.clip(similarity, 0, 1)

            # Accumulate sum and sum of squares for upper triangular part
            if i < num_trees - 1:
                upper_part = similarity[i + 1:]
                total_sum += np.sum(upper_part)
                total_sum_sq += np.sum(upper_part ** 2)

            # Save to similarity matrix
            similarity_matrix[i, :] = similarity.astype('float32')

        total_elements = num_trees * (num_trees - 1) / 2

    similarity_matrix.flush()
    print(f"Similarity matrix has been saved to '{similarity_matrix_path}'")

    # Calculate mean and variance
    average = total_sum / total_elements
    variance = (total_sum_sq / total_elements) - (average ** 2)

    return similarity_matrix, average, variance


def main():
    parser = argparse.ArgumentParser(description="Generate similarity matrix from tree edit distance matrix.")
    parser.add_argument(
        "--trees_pickle",
        type=str,
        default="trees_AST_POC_MIXED.pkl",
        help="Path to pickle file containing tree data (default: trees_AST_ER.pkl)"
    )
    parser.add_argument(
        "--distance_matrix",
        type=str,
        default="cost1-distance_matrix_POC_MIXED.dat",
        help="Path to memory-mapped file of tree edit distance matrix (default: cost1-distance_matrix_POC_MIXED.dat)"
    )
    parser.add_argument(
        "--method",
        type=str,
        choices=['NTED1', 'NTED2', 'NTED3', 'minmax'],
        default='NTED1',
        help="Choose normalization method: NTED1 (normalization based on node count), NTED2 (normalization based on maximum possible edit distance), NTED3 (based on maximum weight in insert and delete operations). Default: NTED1"
    )
    parser.add_argument(
        "--a",
        type=int,
        default=100,
        help="Parameter a in normalization method NTED3 (default: 1000)"
    )
    parser.add_argument(
        "--normalize_type",
        type=str,
        choices=['NTED1', 'NTED2', 'NTED3', 'minmax'],
        default='minmax',
        help="Choose normalization type: 'minmax' or other normalization methods (default: None)."
    )
    parser.add_argument(
        "--similarity_output",
        type=str,
        default=None,
        help="Output path for similarity matrix file. If not specified, will be automatically named based on selected normalization method."
    )

    args = parser.parse_args()

    trees_pickle_path = args.trees_pickle
    distance_matrix_path = args.distance_matrix
    method = args.method
    a = args.a
    similarity_output = args.similarity_output
    normalize_type = args.normalize_type

    if not os.path.isfile(trees_pickle_path):
        print(f"Error: File '{trees_pickle_path}' does not exist.")
        return

    if not os.path.isfile(distance_matrix_path):
        print(f"Error: File '{distance_matrix_path}' does not exist.")
        return

    print("Loading tree data...")
    trees_list = load_trees_pickle(trees_pickle_path)
    node_counts = get_node_counts(trees_list)
    num_trees = len(node_counts)
    print(f"Loaded {num_trees} trees.")

    print("Loading tree edit distance matrix...")
    ted_matrix = np.memmap(distance_matrix_path, dtype='float32', mode='r', shape=(num_trees, num_trees))
    print("Tree edit distance matrix loading completed.")

    if similarity_output is None:
        similarity_matrix_path = f"similarity_matrix_{method}.dat"
    else:
        similarity_matrix_path = similarity_output

    print("Starting normalization and similarity matrix computation...")
    similarity_matrix, average, variance = normalize_ted_matrix(ted_matrix, node_counts, method=method, a=a)

    print("Similarity matrix computation completed.")
    print(f"Similarity matrix mean: {average:.6f}")
    print(f"Similarity matrix variance: {variance:.6f}")

    # If needed, save mean and variance to a text file
    stats_output = f"similarity_stats_{method}.txt" if similarity_output is None else f"{os.path.splitext(similarity_output)[0]}_stats.txt"
    with open(stats_output, "w") as f:
        f.write(f"Normalization method: {method}\n")
        f.write(f"Similarity matrix mean: {average:.6f}\n")
        f.write(f"Similarity matrix variance: {variance:.6f}\n")
    print(f"Similarity matrix statistics have been saved to '{stats_output}'")


if __name__ == "__main__":
    main()
