import os
import json


def traverse_args(args, nodes, adj, parent_index):
    """
    Recursively traverse arguments and their sub-arguments to build nodes and adjacency lists.

    Args:
        args (list): List of argument dictionaries.
        nodes (list): List to add node labels to.
        adj (list): List to add adjacency lists to.
        parent_index (int): Index of the parent node in nodes.

    Returns:
        None
    """
    children = []
    for arg in args:
        # Create label for current argument
        arg_type = arg.get("type", "UnknownType")
        arg_value = arg.get("value", "")
        if isinstance(arg_value, int):
            arg_label = f"{arg_type}: {arg_value}"
        elif isinstance(arg_value, str) and arg_type != "*prog.GroupArg":
            arg_label = f"{arg_type}: {arg_value}"
        else:
            arg_label = f"{arg_type}"

        nodes.append(arg_label)
        adj.append([])  # Add corresponding adjacency list
        current_index = len(nodes) - 1
        children.append(current_index)

        # If there are sub-arguments, process them recursively
        sub_args = arg.get("sub_args", [])
        if sub_args:
            traverse_args(sub_args, nodes, adj, current_index)

    adj[parent_index].extend(children)


def process_program_ast(program_ast):
    """
    Process a single ProgramAST JSON object to generate nodes and adjacency lists.

    Args:
        program_ast (dict): ProgramAST JSON object.

    Returns:
        tuple: Tuple containing node list and adjacency list.
    """
    nodes = ["ProgramAST"]  # Virtual root node
    adj = [[]]              # Initialize adjacency list including root node

    calls = program_ast.get("calls", [])
    for call in calls:
        # Add call name as child of ProgramAST
        call_name = call.get("name", "UnnamedCall")
        nodes.append(call_name)
        adj.append([])  # Add adjacency list for new call node
        call_index = len(nodes) - 1
        adj[0].append(call_index)

        # Process call arguments
        args = call.get("args", [])
        traverse_args(args, nodes, adj, call_index)

    return nodes, adj


def main():
    # Define AST directory path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    ast_directory = os.path.join(parent_dir, "seed", "AST_POC_MIXED")

    # Define output file path
    map_output = "map_AST_POC_MIXED.json"

    ast_map = {}

    # Check if AST directory exists
    if not os.path.isdir(ast_directory):
        print(f"Directory '{ast_directory}' does not exist. Please ensure the directory exists and contains JSON files.")
        return

    # Traverse all JSON files in AST directory
    for filename in os.listdir(ast_directory):
        if filename.endswith(".json"):
            filepath = os.path.join(ast_directory, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as file:
                    program_ast = json.load(file)
            except json.JSONDecodeError as e:
                print(f"Unable to parse JSON content of file '{filename}': {e}")
                continue

            # Use filename (without extension) as key
            syscall_hash = os.path.splitext(filename)[0]

            # Process ProgramAST to get nodes and adjacency list
            try:
                nodes, adj = process_program_ast(program_ast)
            except IndexError as e:
                print(f"Error occurred while processing file '{filename}': {e}")
                continue

            # Add to ast_map using hash as key
            ast_map[syscall_hash] = {"nodes": nodes, "adj": adj}

    # Save map to JSON file
    with open(map_output, "w", encoding="utf-8") as map_file:
        json.dump(ast_map, map_file, indent=2, ensure_ascii=False)

    print(f"Processed {len(ast_map)} AST trees.")
    print(f"Map saved to '{map_output}'")


if __name__ == "__main__":
    main()
