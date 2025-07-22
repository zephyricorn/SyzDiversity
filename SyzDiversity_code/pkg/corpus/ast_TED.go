package corpus

import (
	"fmt"
	"reflect"

	"github.com/google/syzkaller/prog"
)

// ProgramAST represents the abstract syntax tree of a program
type ProgramAST struct {
	Nodes []string // Tree node labels
	Adj   [][]int  // Tree adjacency list
}

// ArgInfo represents argument information
type ArgInfo struct {
	Type    string      `json:"type"`
	Val     interface{} `json:"val,omitempty"`
	SubArgs []ArgInfo   `json:"subArgs,omitempty"`
}

// CallInfo represents call information
type CallInfo struct {
	Name string    `json:"name"`
	Args []ArgInfo `json:"args"`
}

// BuildProgramAST builds the AST of a program
func buildProgramAST(p *prog.Prog) (*ProgramAST, error) {
	if p == nil {
		return nil, fmt.Errorf("nil program")
	}

	ast := &ProgramAST{
		Nodes: []string{"ROOT"}, // Root node
		Adj:   [][]int{{}},      // Root node adjacency list, initially empty
	}

	// Add nodes for each call
	for _, call := range p.Calls {
		// Add call node
		callNodeIdx := len(ast.Nodes)
		callNodeName := fmt.Sprintf("CALL:%s", call.Meta.Name)
		ast.Nodes = append(ast.Nodes, callNodeName)

		// Add call node as a child of the root node
		ast.Adj[0] = append(ast.Adj[0], callNodeIdx)
		ast.Adj = append(ast.Adj, []int{})

		// Process call arguments
		processArgs(call.Args, callNodeIdx, ast)
	}

	return ast, nil
}

// Process arguments and add them to the AST
func processArgs(args []prog.Arg, parentIdx int, ast *ProgramAST) {
	for _, arg := range args {
		if arg == nil {
			continue
		}

		// Add argument node
		argNodeIdx := len(ast.Nodes)
		argNodeName := fmt.Sprintf("ARG:%s", reflect.TypeOf(arg).String())
		ast.Nodes = append(ast.Nodes, argNodeName)

		// Add argument node as a child of parent node
		ast.Adj[parentIdx] = append(ast.Adj[parentIdx], argNodeIdx)
		ast.Adj = append(ast.Adj, []int{})

		// Process based on argument type
		switch a := arg.(type) {
		case *prog.ConstArg:
			valNodeIdx := len(ast.Nodes)
			valNodeName := fmt.Sprintf("VAL:%v", a.Val)
			ast.Nodes = append(ast.Nodes, valNodeName)
			ast.Adj[argNodeIdx] = append(ast.Adj[argNodeIdx], valNodeIdx)
			ast.Adj = append(ast.Adj, []int{})

		case *prog.DataArg:
			if a.Dir() != prog.DirOut {
				valNodeIdx := len(ast.Nodes)
				valNodeName := fmt.Sprintf("DATA:%x", a.Data())
				ast.Nodes = append(ast.Nodes, valNodeName)
				ast.Adj[argNodeIdx] = append(ast.Adj[argNodeIdx], valNodeIdx)
				ast.Adj = append(ast.Adj, []int{})
			}

		case *prog.GroupArg:
			for _, inner := range a.Inner {
				processArgs([]prog.Arg{inner}, argNodeIdx, ast)
			}

		case *prog.PointerArg:
			valNodeIdx := len(ast.Nodes)
			valNodeName := fmt.Sprintf("ADDR:%v", a.Address)
			ast.Nodes = append(ast.Nodes, valNodeName)
			ast.Adj[argNodeIdx] = append(ast.Adj[argNodeIdx], valNodeIdx)
			ast.Adj = append(ast.Adj, []int{})

			if a.Res != nil {
				processArgs([]prog.Arg{a.Res}, argNodeIdx, ast)
			}

		case *prog.UnionArg:
			if a.Option != nil {
				processArgs([]prog.Arg{a.Option}, argNodeIdx, ast)
			}

		case *prog.ResultArg:
			valNodeIdx := len(ast.Nodes)
			valName := fmt.Sprintf("%v", a.Val)
			if a.Res != nil {
				valName = fmt.Sprintf("ref=%v", a.Res.Val)
			}
			valNodeName := fmt.Sprintf("RES:%s", valName)
			ast.Nodes = append(ast.Nodes, valNodeName)
			ast.Adj[argNodeIdx] = append(ast.Adj[argNodeIdx], valNodeIdx)
			ast.Adj = append(ast.Adj, []int{})
		}
	}
}

// CalculateTED calculates the Tree Edit Distance between two trees
// Implements the Zhang-Shasha algorithm
func CalculateTED(xNodes []string, xAdj [][]int, yNodes []string, yAdj [][]int) int {
	if len(xNodes) == 0 || len(yNodes) == 0 {
		return max(len(xNodes), len(yNodes))
	}

	// Get post-order traversal
	xPostOrder := postOrderTraversal(xAdj, 0, nil)
	yPostOrder := postOrderTraversal(yAdj, 0, nil)

	// Get left subtree key root nodes
	xLRKeyRoots := computeLRKeyRoots(xAdj, 0)
	yLRKeyRoots := computeLRKeyRoots(yAdj, 0)

	// Initialize distance matrix
	n := len(xNodes)
	m := len(yNodes)
	treedist := make([][]int, n)
	for i := range treedist {
		treedist[i] = make([]int, m)
	}

	// Calculate distances between subtrees
	for _, i := range xLRKeyRoots {
		for _, j := range yLRKeyRoots {
			treeEditDist(i, j, xNodes, yNodes, xAdj, yAdj, xPostOrder, yPostOrder, treedist)
		}
	}

	return treedist[0][0]
}

// Post-order traversal of tree, with result reuse option
func postOrderTraversal(adj [][]int, node int, result []int) []int {
    // Estimate final result size to avoid frequent reallocations
    estimatedSize := len(adj)
    if result == nil {
        result = make([]int, 0, estimatedSize)
    }

    for _, child := range adj[node] {
        result = postOrderTraversal(adj, child, result)
    }

    return append(result, node)
}

// Calculate left-right key root nodes
func computeLRKeyRoots(adj [][]int, root int) []int {
	result := []int{root}
	for _, child := range adj[root] {
		result = append(result, computeLRKeyRoots(adj, child)...)
	}
	return result
}

// Tree edit distance calculation
func treeEditDist(i, j int, xNodes, yNodes []string, xAdj, yAdj [][]int, xPostOrder, yPostOrder []int, treedist [][]int) {
    // Get subtree sizes
    xSize := len(postOrderTraversal(xAdj, i, nil))
    ySize := len(postOrderTraversal(yAdj, j, nil))

    // Initialize forest distance matrix
    forestdist := make([][]int, xSize+1)
    for idx := range forestdist {
        forestdist[idx] = make([]int, ySize+1)
    }

    // Initialize boundary conditions
    forestdist[0][0] = 0
    for i1 := 1; i1 <= xSize; i1++ {
        forestdist[i1][0] = forestdist[i1-1][0] + 1
    }
    for j1 := 1; j1 <= ySize; j1++ {
        forestdist[0][j1] = forestdist[0][j1-1] + 1
    }

    // Calculate forest distance
    for i1 := 1; i1 <= xSize; i1++ {
        for j1 := 1; j1 <= ySize; j1++ {
            // Get current node indices in original trees
            iIdx := xPostOrder[i1-1]
            jIdx := yPostOrder[j1-1]

            // Calculate costs of delete, insert, and replace operations
            if xNodes[iIdx] == yNodes[jIdx] {
                forestdist[i1][j1] = forestdist[i1-1][j1-1] // Same node, no editing needed
            } else {
                // Take minimum of three operations
                deleteCost := forestdist[i1-1][j1] + 1
                insertCost := forestdist[i1][j1-1] + 1
                replaceCost := forestdist[i1-1][j1-1] + 1

                forestdist[i1][j1] = min3(deleteCost, insertCost, replaceCost)
            }
        }
    }

    // Update tree edit distance
    treedist[i][j] = forestdist[xSize][ySize]
    
    // Explicitly release temporary memory
    for idx := range forestdist {
        forestdist[idx] = nil
    }
    forestdist = nil
}

// Helper functions
func min3(a, b, c int) int {
	return min(min(a, b), c)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
