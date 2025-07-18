package corpus

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"math"
	"time"
    "math/rand"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// ClusterCenter represents cluster center data
type ClusterCenter struct {
	ClusterID int        // Cluster ID
	SeedHash  string     // Seed hash value
	Program   *prog.Prog // Seed program
	TreeNodes []string   // AST tree nodes
	TreeAdj   [][]int    // AST tree adjacency list
}

// ClusterInfo stores cluster information and access statistics
type ClusterInfo struct {
	ProgramHashes    map[string]int    // Mapping from program hash to cluster ID
	ClusterSizes     map[int]int       // Size of each cluster (number of programs)
	LastAccess       map[int]time.Time // Last access time for each cluster
	AccessCount      map[int]int       // Access count for each cluster
	ClusterCenters   map[int]*ClusterCenter // Cluster center information
	TotalAccess      int               // Total access count
	DefaultClusterID int               // Default cluster ID
	MaxClusterID     int               // Current maximum cluster ID, reserved for future expansion

	similarityThreshold float64 // Similarity threshold
	mu                  sync.RWMutex
	target              *prog.Target // Target for program parsing

	// --- Modified for UCB and Memory Optimization ---
	ClusterSumRewards   map[int]float64 // Cumulative reward sum for each cluster (based on processResult cluster reward calculation)
	ClusterRewardCounts map[int]int       // Number of times each cluster has been rewarded

	SeedSumRewards      map[string]float64 // Cumulative reward sum for each seed (based on Δcov)
	SeedRewardCounts  map[string]int       // Number of times each seed has been rewarded (based on Δcov)

	SeedCoverageSize    map[string]int         // Seed coverage size records
	CoverLastUpdate     map[string]time.Time   // Last coverage update time (update time for SeedCoverageSize)
	SeedExecutionTime   map[string]time.Duration // Seed execution time records
	SeedBugCount        map[string]int         // Number of bugs found by each seed
	SeedAccessCount     map[string]int         // Seed access count (updated by recordAccess in ChooseProgramCommunityUCB)
	TotalCoverage       signal.Signal          // Total coverage (union of all seed coverage)
	ExplorationRate     float64                // Cluster popularity adjustment coefficient α
	SeedClusterMap      map[string]int         // Mapping from seed to cluster
	TotalClusterSize    int                    // Total size of all clusters (sum of all ClusterSizes[id])
	ClusterExploreCoef  float64                // Community UCB exploration term scaling coefficient
	SeedExploreCoef     float64                // Seed UCB exploration term scaling coefficient
	
	// New fields for tracking mutant offspring performance
	SeedMutantCoverages map[string][]int       // Track coverage sizes of mutant offspring for each seed
	SeedMutantCrashes   map[string][]int       // Track crash counts of mutant offspring for each seed
	// --- End Modified Fields ---

	// Cache mechanism (Ensure these have proper management if used)
	cachedBestClusters    []int
	cachedClusterPrograms map[int][]*prog.Prog
	cachedBestSeeds       map[int][]*prog.Prog
	lastCacheUpdate       time.Time

	astCacheSize    int                  // Current AST cache size
	maxASTCacheSize int                  // Maximum AST cache size
	astCacheQueue   []string             // Cache queue for LRU eviction
	astLastAccess   map[string]time.Time // Record last access time for each AST
	lastCleanupTime time.Time            // Last cleanup execution time

	// Coverage estimation related
	EstimatedCovCache map[string]int // Cache for estimated coverage

	// Debug assistance
	CoverageStats struct {
		TotalRequests int // Total number of requests
		ZeroValues    int // Number of times zero values are returned
		ActualUsed    int // Number of times actual coverage is used
	}

	// Memory management configuration
	maxSeedEntries      int           // Maximum number of seed entries
	maxCoverageHistory  int           // Maximum number of coverage history records
	cleanupInterval     time.Duration // Cleanup interval
	lastMemoryCleanup   time.Time     // Last memory cleanup time
}

// NewClusterInfo creates a new ClusterInfo instance
func NewClusterInfo() *ClusterInfo {
	return &ClusterInfo{
		ProgramHashes:    make(map[string]int),
		ClusterSizes:     make(map[int]int),
		LastAccess:       make(map[int]time.Time),
		AccessCount:      make(map[int]int),
		ClusterCenters:   make(map[int]*ClusterCenter),
		DefaultClusterID: 0,   // Default cluster ID is 0
		similarityThreshold: 0.4, // Default similarity threshold

		// Initialize new and modified fields
		ClusterSumRewards:   make(map[int]float64),
		ClusterRewardCounts: make(map[int]int),
		SeedSumRewards:      make(map[string]float64),
		SeedRewardCounts:    make(map[string]int),

		SeedCoverageSize:    make(map[string]int),
		CoverLastUpdate:     make(map[string]time.Time),
		SeedExecutionTime:   make(map[string]time.Duration),
		SeedBugCount:        make(map[string]int),
		SeedAccessCount:     make(map[string]int),
		TotalCoverage:       make(signal.Signal),
		ExplorationRate:     0.3, // Default community popularity adjustment coefficient α is 0.3
		ClusterExploreCoef:  1.0, // Default community UCB exploration coefficient is 1.0
		SeedExploreCoef:     1.0, // Default seed UCB exploration coefficient is 1.0
		SeedClusterMap:      make(map[string]int),
		TotalClusterSize:    0,   // Initialize to 0
		
		// Initialize new fields for tracking mutant offspring
		SeedMutantCoverages: make(map[string][]int),
		SeedMutantCrashes:   make(map[string][]int),

		// Initialize AST cache control
		astCacheSize:    0,
		maxASTCacheSize: 1000, // Default maximum cache of 1000 ASTs, can be adjusted based on system memory
		astCacheQueue:   make([]string, 0),
		astLastAccess:   make(map[string]time.Time),
		lastCleanupTime: time.Now(),

		EstimatedCovCache: make(map[string]int),

		// Initialize memory management configuration
		maxSeedEntries:     80000,                // Maximum 80000 seed entries
		maxCoverageHistory: 100000,               // Maximum 100000 coverage history records
		cleanupInterval:    60 * time.Minute,     // Cleanup every 60 minutes
		lastMemoryCleanup:  time.Now(),
	}
}

// SetTarget sets the target for program parsing
func (c *ClusterInfo) SetTarget(target *prog.Target) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.target = target
}

// SetSimilarityThreshold sets the similarity threshold
func (c *ClusterInfo) SetSimilarityThreshold(threshold float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.similarityThreshold = threshold
}

// GetSimilarityThreshold gets the similarity threshold
func (c *ClusterInfo) GetSimilarityThreshold() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.similarityThreshold
}

// LoadClusterCores loads cluster center seed information from CSV file
func (c *ClusterInfo) LoadClusterCores(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// File does not exist, not considered an error
			return nil
		}
		return err
	}
	defer file.Close()

	r := csv.NewReader(file)

	// Skip header row
	if _, err := r.Read(); err != nil {
		return err
	}

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Parse cluster ID and seed hash
		clusterID, err := strconv.Atoi(record[0])
		if err != nil {
			return err
		}

		seedHash := record[1]

		// Create cluster center object
		center := &ClusterCenter{
			ClusterID: clusterID,
			SeedHash:  seedHash,
		}

		c.ClusterCenters[clusterID] = center

		// Update maximum cluster ID
		if clusterID > c.MaxClusterID {
			c.MaxClusterID = clusterID
		}
	}

	return nil
}

// LoadFromCSV loads cluster information from CSV file
func (c *ClusterInfo) LoadFromCSV(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	r := csv.NewReader(file)

	// Skip header row
	if _, err := r.Read(); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		hash := record[0]
		clusterID, err := strconv.Atoi(record[1])
		if err != nil {
			return err
		}

		c.ProgramHashes[hash] = clusterID
		c.ClusterSizes[clusterID]++

		// Update maximum cluster ID for future expansion
		if clusterID > c.MaxClusterID {
			c.MaxClusterID = clusterID
		}
	}

	return nil
}

// SaveClusterLabel saves cluster information to CSV file
func (c *ClusterInfo) SaveClusterLabel(path string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := csv.NewWriter(file)
	defer w.Flush()

	// Write header row
	if err := w.Write([]string{"ProgramHash", "ClusterID"}); err != nil {
		return err
	}

	// Write cluster information for each program
	for hash, clusterID := range c.ProgramHashes {
		record := []string{hash, strconv.Itoa(clusterID)}
		if err := w.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// SaveClusterCores saves cluster center information to CSV file
func (c *ClusterInfo) SaveClusterCores(path string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := csv.NewWriter(file)
	defer w.Flush()

	// Write header row
	if err := w.Write([]string{"ClusterID", "SeedHash"}); err != nil {
		return err
	}

	// Write information for each cluster center
	for clusterID, center := range c.ClusterCenters {
		if center == nil || center.SeedHash == "" {
			continue // Skip invalid centers
		}

		record := []string{strconv.Itoa(clusterID), center.SeedHash}
		if err := w.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// SaveClusterASTs saves cluster center AST information to specified directory
func (c *ClusterInfo) SaveClusterASTs(dirPath string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Ensure directory exists
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return fmt.Errorf("failed to create AST directory: %v", err)
	}

	// Save AST for each cluster center
	for clusterID, center := range c.ClusterCenters {
		if center == nil || center.Program == nil || center.SeedHash == "" {
			continue // Skip invalid centers
		}

		// Only save AST when node list has been generated
		if len(center.TreeNodes) > 0 {
			// Create JSON format AST data
			ast := map[string]interface{}{
				"nodes": center.TreeNodes,
				"adj":   center.TreeAdj,
			}

			// Save AST as JSON file
			fileName := fmt.Sprintf("%s.json", center.SeedHash)
			filePath := filepath.Join(dirPath, fileName)

			jsonData, err := json.MarshalIndent(ast, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal AST for cluster %d: %v", clusterID, err)
			}

			if err := ioutil.WriteFile(filePath, jsonData, 0644); err != nil {
				return fmt.Errorf("failed to write AST file for cluster %d: %v", clusterID, err)
			}
		}
	}

	return nil
}

// AssignDefaultCluster assigns default cluster for new seed
func (c *ClusterInfo) AssignDefaultCluster(hash string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if cluster ID already exists
	if clusterID, exists := c.ProgramHashes[hash]; exists {
		return clusterID
	}

	// Assign default cluster ID
	c.ProgramHashes[hash] = c.DefaultClusterID
	c.ClusterSizes[c.DefaultClusterID]++
	c.TotalClusterSize++ // Update total cluster size
	return c.DefaultClusterID
}

// RecordAccess records access to a specific cluster
func (c *ClusterInfo) RecordAccess(hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var clusterID int

	// Get or assign cluster ID
	if id, exists := c.ProgramHashes[hash]; exists {
		clusterID = id
	} else {
		// If no cluster ID, assign default cluster
		clusterID = c.DefaultClusterID
		c.ProgramHashes[hash] = clusterID
		c.ClusterSizes[clusterID]++
		c.TotalClusterSize++ // Update total cluster size
	}

	c.AccessCount[clusterID]++
	c.LastAccess[clusterID] = time.Now()
	c.TotalAccess++
}

// GetClusterID gets the cluster ID that a program belongs to
func (c *ClusterInfo) GetClusterID(hash string) (int, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	id, exists := c.ProgramHashes[hash]
	if !exists { // If not in ProgramHashes, try to get from SeedClusterMap
		id, exists = c.SeedClusterMap[hash]
	}
	return id, exists
}

// GetClusterSize gets the size of a cluster
func (c *ClusterInfo) GetClusterSize(clusterID int) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ClusterSizes[clusterID]
}

// GetAccessCount gets the access count for a specific cluster
func (c *ClusterInfo) GetAccessCount(clusterID int) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.AccessCount[clusterID]
}

// UpdateClusterAccess updates the access information for a cluster
func (c *ClusterInfo) UpdateClusterAccess(clusterID int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.AccessCount[clusterID]++
	c.LastAccess[clusterID] = time.Now()
	c.TotalAccess++
}

// SetDefaultClusterID sets the default cluster ID
func (c *ClusterInfo) SetDefaultClusterID(id int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.DefaultClusterID = id
}

// AssignCluster assigns a cluster for a new seed based on TED similarity
func (c *ClusterInfo) AssignCluster(prog *prog.Prog, progHash string) (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If program already has a cluster ID, return it
	if clusterID, exists := c.ProgramHashes[progHash]; exists {
		c.SeedClusterMap[progHash] = clusterID // Ensure SeedClusterMap is updated
		return clusterID, false
	}
	// Also check SeedClusterMap
	if clusterID, exists := c.SeedClusterMap[progHash]; exists {
		return clusterID, false
	}

	// If no cluster centers or target is set, assign default cluster
	if len(c.ClusterCenters) == 0 || c.target == nil {
		return c.assignDefaultClusterLocked(progHash), false
	}

	// Construct AST for new program
	newProgAST, err := buildProgramAST(prog)
	if err != nil {
		log.Logf(1, "failed to build AST for new program %s: %v, assigning to default cluster", progHash, err)
		return c.assignDefaultClusterLocked(progHash), false
	}

	newProgSize := len(newProgAST.Nodes)

	bestClusterID := -1
	bestSimilarity := 0.0
	// similarities := make(map[int]float64) // If not needed, can remove

	for clusterID, center := range c.ClusterCenters {
		if center.Program == nil {
			continue
		}
		if len(center.TreeNodes) == 0 { // Lazy load cluster center AST
			centerAST, errBuild := buildProgramAST(center.Program)
			if errBuild != nil {
				log.Logf(1, "failed to build AST for cluster %d center: %v", clusterID, errBuild)
				continue
			}
			center.TreeNodes = centerAST.Nodes
			center.TreeAdj = centerAST.Adj
		}

		centerSize := len(center.TreeNodes)
		distance := CalculateTED(newProgAST.Nodes, newProgAST.Adj, center.TreeNodes, center.TreeAdj)
		maxPossibleDistance := newProgSize + centerSize
		similarity := 0.0
		if maxPossibleDistance > 0 {
			similarity = 1.0 - (float64(distance) / float64(maxPossibleDistance))
		}
		// similarities[clusterID] = similarity // If not needed, can remove

		if similarity > bestSimilarity {
			bestSimilarity = similarity
			bestClusterID = clusterID
		}
	}

	if bestSimilarity >= c.similarityThreshold && bestClusterID != -1 {
		c.ProgramHashes[progHash] = bestClusterID
		c.SeedClusterMap[progHash] = bestClusterID // Update SeedClusterMap
		c.ClusterSizes[bestClusterID]++
		c.TotalClusterSize++ // Update total cluster size
		return bestClusterID, false
	}

	newClusterID := c.MaxClusterID + 1
	c.MaxClusterID = newClusterID
	newCenter := &ClusterCenter{
		ClusterID: newClusterID, SeedHash:  progHash, Program:   prog,
		TreeNodes: newProgAST.Nodes, TreeAdj:   newProgAST.Adj,
	}
	c.ClusterCenters[newClusterID] = newCenter
	c.ProgramHashes[progHash] = newClusterID
	c.SeedClusterMap[progHash] = newClusterID // Update SeedClusterMap
	c.ClusterSizes[newClusterID] = 1
	c.TotalClusterSize++ // Update total cluster size
	return newClusterID, true
}

// Helper method, assigns default cluster under locked condition
func (c *ClusterInfo) assignDefaultClusterLocked(hash string) int {
	// Ensure SeedClusterMap is also updated
	if _, exists := c.ProgramHashes[hash]; !exists {
		c.ClusterSizes[c.DefaultClusterID]++
		c.TotalClusterSize++ // Update total cluster size
	}
	c.ProgramHashes[hash] = c.DefaultClusterID
	c.SeedClusterMap[hash] = c.DefaultClusterID
	return c.DefaultClusterID
}

// StoreProgramInCluster stores a program in a cluster center
func (c *ClusterInfo) StoreProgramInCluster(p *prog.Prog, hash string, clusterID int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if center, exists := c.ClusterCenters[clusterID]; exists && center.SeedHash == hash {
		center.Program = p
	}
}

// UpdateClusterCenter updates or sets a cluster center
func (c *ClusterInfo) UpdateClusterCenter(clusterID int, p *prog.Prog, hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	center, exists := c.ClusterCenters[clusterID]
	if !exists {
		center = &ClusterCenter{ ClusterID: clusterID }
		c.ClusterCenters[clusterID] = center
	}
	center.Program = p
	center.SeedHash = hash
	center.TreeNodes = nil // Clear old AST, wait for next time to rebuild
	center.TreeAdj = nil
}

// CalculateClusterDensity calculates the density of a cluster
func (c *ClusterInfo) CalculateClusterDensity(clusterID int) float64 {
    c.mu.RLock() // Read-only operation, use read lock
    defer c.mu.RUnlock()
    
    if c.TotalClusterSize == 0 { return 0.0 }
    return float64(c.ClusterSizes[clusterID]) / float64(c.TotalClusterSize)
}

// CalculateCPR calculates community popularity
func (c *ClusterInfo) CalculateCPR(clusterID int) float64 {
    density := c.CalculateClusterDensity(clusterID) // Internal read lock
    if density == 0 { return 0.0 }
    
    c.mu.RLock() // Read-only operation, use read lock
    visits := float64(c.AccessCount[clusterID])
    c.mu.RUnlock()
    
    return visits / density
}

// CalculateSeedCoverageContribution calculates the coverage contribution of a seed
func (c *ClusterInfo) CalculateSeedCoverageContribution(seedHash string) float64 {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    size, exists := c.SeedCoverageSize[seedHash]
    if !exists {
        return 0.0
    }
    return float64(size) // Return total coverage size of seed itself
}

// UpdateSeedExecutionTime updates the execution time of a seed
func (c *ClusterInfo) UpdateSeedExecutionTime(seedHash string, execTime time.Duration) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if c.SeedExecutionTime == nil { c.SeedExecutionTime = make(map[string]time.Duration) }
    c.SeedExecutionTime[seedHash] = execTime
}

// UpdateSeedBugCount updates the number of bugs found by a seed
func (c *ClusterInfo) UpdateSeedBugCount(seedHash string, bugCount int) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if c.SeedBugCount == nil { c.SeedBugCount = make(map[string]int) }
    c.SeedBugCount[seedHash] += bugCount
}

func (c *ClusterInfo) UpdateCoverage(seedHash string, newCoverage signal.Signal) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    // Get cluster ID for the seed
    clusterID, exists := c.SeedClusterMap[seedHash]
    if !exists {
        clusterID, exists = c.ProgramHashes[seedHash]
        if !exists {
            log.Logf(1, "UpdateCoverage: seed %s has no cluster information", seedHash)
            return // No cluster information, cannot continue
        }
        c.SeedClusterMap[seedHash] = clusterID // Ensure mapping exists
    }
  
    
    newCoverageSize := newCoverage.Len()


    c.SeedCoverageSize[seedHash] = newCoverageSize // Update size

    // Update total coverage
    if c.TotalCoverage == nil { c.TotalCoverage = make(signal.Signal) }
    c.TotalCoverage.Merge(newCoverage) // Merge complete signal


    // Update last coverage time
    if c.CoverLastUpdate == nil { c.CoverLastUpdate = make(map[string]time.Time) }
    c.CoverLastUpdate[seedHash] = time.Now()


    log.Logf(2, "UpdateCoverage : seed %s, new coverage size %d, total coverage size %d", seedHash, newCoverageSize, c.TotalCoverage.Len())
}

// RecordSeedAccess records seed access and increases access count
func (c *ClusterInfo) RecordSeedAccess(seedHash string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    if c.SeedAccessCount == nil { c.SeedAccessCount = make(map[string]int) }
    c.SeedAccessCount[seedHash]++
    
    clusterID, exists := c.SeedClusterMap[seedHash]
    if !exists {
        clusterID, exists = c.ProgramHashes[seedHash]
        if !exists {
            // log.Logf(0, "RecordSeedAccess: seed %s has no cluster information", seedHash)
            return // If no cluster, at least recorded seed access
        }
        c.SeedClusterMap[seedHash] = clusterID // Ensure mapping
    }
    
    if c.AccessCount == nil { c.AccessCount = make(map[int]int) }
    c.AccessCount[clusterID]++
    if c.LastAccess == nil { c.LastAccess = make(map[int]time.Time) }
    c.LastAccess[clusterID] = time.Now()
    c.TotalAccess++
}

// CalculateClusterInstantReward calculates the instant reward for a cluster
func (c *ClusterInfo) CalculateClusterInstantReward(clusterID int) float64 {
    c.mu.RLock() // Read-only operation
    defer c.mu.RUnlock()
    
    clusterSize := c.ClusterSizes[clusterID]
    if clusterSize == 0 { return 0.0 }
    
    var totalCoverageSize float64 // Note: This is float64
    var seedCountInCluster int
    
    for seedHash, id := range c.SeedClusterMap {
        if id == clusterID {

            if size, exists := c.SeedCoverageSize[seedHash]; exists {
                totalCoverageSize += float64(size)
                seedCountInCluster++
            }
        }
    }
    
    var avgCoverage float64
    if seedCountInCluster > 0 {
        avgCoverage = totalCoverageSize / float64(seedCountInCluster)
    }
    
    // CalculateCPR internal will lock
    cpr := c.CalculateCPR(clusterID) 

    reward := avgCoverage + c.ExplorationRate * cpr 
    return reward
}

func (c *ClusterInfo) UpdateClusterReward(clusterID int, reward float64) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    if _, exists := c.ClusterSumRewards[clusterID]; !exists {
        c.ClusterSumRewards[clusterID] = 0.0
        c.ClusterRewardCounts[clusterID] = 0
    }
    c.ClusterSumRewards[clusterID] += reward
    c.ClusterRewardCounts[clusterID]++
}

// CalculateClusterAverageReward calculates the average reward for a cluster
func (c *ClusterInfo) CalculateClusterAverageReward(clusterID int) float64 {
    c.mu.RLock() // Read
    defer c.mu.RUnlock()
    
    count := c.ClusterRewardCounts[clusterID]
    if count == 0 {
        return 0.0 // No reward record, average is 0
    }
    sum := c.ClusterSumRewards[clusterID]
    return sum / float64(count)
}

// CalculateClusterUCB calculates the UCB score for a cluster
func (c *ClusterInfo) CalculateClusterUCB(clusterID int) float64 {
    // CalculateClusterAverageReward internal will lock
    avgReward := c.CalculateClusterAverageReward(clusterID)
    
    c.mu.RLock() // Lock for other fields
    totalRounds := c.TotalAccess + 1 
    visits := float64(c.AccessCount[clusterID]) + 1.0
    exploreScale := c.ClusterExploreCoef
    c.mu.RUnlock()
    
    exploreCoef := math.Sqrt(2.0) // Standard UCB1 exploration constant
    exploreScore := exploreScale * exploreCoef * math.Sqrt(math.Log(float64(totalRounds))/visits)
    
    ucbScore := avgReward + exploreScore
    // log.Logf(3, "cluster %d UCB calculation: avg reward=%.4f, exploration term=%.4f (scaling factor=%.2f), UCB=%.4f",
    //     clusterID, avgReward, exploreScore, exploreScale, ucbScore)
    return ucbScore
}

// CalculateSeedInstantReward calculates the instant reward for a seed
func (c *ClusterInfo) CalculateSeedInstantReward(seedHash string) float64 {
    c.mu.RLock() // Read
    defer c.mu.RUnlock()

    seedSize, exists := c.SeedCoverageSize[seedHash]
    if !exists { return 0.0 }
    
    currentCov := float64(seedSize) 
    
    execTime := c.SeedExecutionTime[seedHash]
    if execTime == 0 { execTime = time.Millisecond } // Prevent division by zero
    
    bugCount := c.SeedBugCount[seedHash]
    
    execTimeInSeconds := execTime.Seconds()
    if execTimeInSeconds < 0.001 { execTimeInSeconds = 0.001 }
    
    reward := (currentCov / execTimeInSeconds) * math.Log1p(float64(bugCount))
    return reward
}

// UpdateSeedReward updates the reward record for a seed
// This function should now update SeedSumRewards and SeedRewardCounts
func (c *ClusterInfo) UpdateSeedReward(seedHash string, reward float64) {
    c.mu.Lock()
    defer c.mu.Unlock()

    if _, exists := c.SeedSumRewards[seedHash]; !exists {
        c.SeedSumRewards[seedHash] = 0.0
        c.SeedRewardCounts[seedHash] = 0
    }
    c.SeedSumRewards[seedHash] += reward
    c.SeedRewardCounts[seedHash]++
}

// CalculateSeedAverageReward calculates the average reward for a seed
func (c *ClusterInfo) CalculateSeedAverageReward(seedHash string) float64 {
    c.mu.RLock() // Read
    defer c.mu.RUnlock()

    count := c.SeedRewardCounts[seedHash]
    if count == 0 {
        return 0.0 // No reward record, average is 0
    }
    sum := c.SeedSumRewards[seedHash]
    return sum / float64(count)
}

// CalculateSeedUCB calculates the UCB score for a seed
func (c *ClusterInfo) CalculateSeedUCB(seedHash string) float64 {
    // CalculateSeedAverageReward internal will lock
    avgReward := c.CalculateSeedAverageReward(seedHash)
    
    c.mu.RLock() // Lock for other fields
    totalRounds := c.TotalAccess + 1 
    visits := float64(c.SeedAccessCount[seedHash]) + 1.0 // Use SeedAccessCount
    exploreScale := c.SeedExploreCoef
    c.mu.RUnlock()
    
    exploreCoef := math.Sqrt(2.0)
    exploreScore := exploreScale * exploreCoef * math.Sqrt(math.Log(float64(totalRounds))/visits)
    
    ucbScore := avgReward + exploreScore

    return ucbScore
}

func (c *ClusterInfo) UpdateSeedPerformance(seedHash string, coverage signal.Signal, execTime time.Duration, newBugs int) {

    c.UpdateCoverage(seedHash, coverage) // UpdateCoverage internal will lock
    
    c.UpdateSeedExecutionTime(seedHash, execTime) // UpdateSeedExecutionTime internal will lock
    

    if newBugs > 0 { // Only call when new bugs occur, avoid unnecessary write operations
        c.UpdateSeedBugCount(seedHash, newBugs)
    }
  
    log.Logf(2, "UpdateSeedPerformance: performance metrics for seed %s have been updated through subfunctions.", seedHash)
}

// SetExplorationRate sets the community popularity adjustment coefficient α
func (c *ClusterInfo) SetExplorationRate(alpha float64) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    if alpha < 0 { alpha = 0 } else if alpha > 1 { alpha = 1 }
    c.ExplorationRate = alpha
    //log.Logf(0, "set community popularity adjustment coefficient α to: %.4f", alpha)
}

// GetExplorationRate gets the community popularity adjustment coefficient α
func (c *ClusterInfo) GetExplorationRate() float64 {
    c.mu.RLock()
    defer c.mu.RUnlock()
    return c.ExplorationRate
}

// GetClusterStats gets the cluster statistics
func (c *ClusterInfo) GetClusterStats(clusterID int) map[string]interface{} {
    c.mu.RLock() // Lock for multiple fields
    
    stats := make(map[string]interface{})
    stats["cluster_id"] = clusterID
    stats["size"] = c.ClusterSizes[clusterID]
 
    density := c.CalculateClusterDensity(clusterID) 
    cpr := c.CalculateCPR(clusterID)               
    avgReward := c.CalculateClusterAverageReward(clusterID) 
    ucbScore := c.CalculateClusterUCB(clusterID)  
    

    sumReward := c.ClusterSumRewards[clusterID]
    rewardCount := c.ClusterRewardCounts[clusterID]

    c.mu.RUnlock() 

    stats["density"] = density
    stats["access_count"] = c.AccessCount[clusterID] 
    stats["cpr"] = cpr
    

    stats["sum_reward"] = sumReward
    stats["reward_count"] = rewardCount
    stats["avg_reward"] = avgReward
    stats["ucb_score"] = ucbScore
    
    return stats
}

// GetSeedStats gets the seed statistics
func (c *ClusterInfo) GetSeedStats(seedHash string) map[string]interface{} {
    c.mu.RLock() // Lock for read
    
    stats := make(map[string]interface{})
    stats["seed_hash"] = seedHash
    clusterID, _ := c.SeedClusterMap[seedHash] // Ignore exists, if not exists is 0 or empty
    if clusterID == 0 { // Try to get from ProgramHashes
        clusterID, _ = c.ProgramHashes[seedHash]
    }
    stats["cluster_id"] = clusterID
    
    stats["coverage_size"] = c.SeedCoverageSize[seedHash] // Use new field
    stats["bug_count"] = c.SeedBugCount[seedHash]
    stats["access_count"] = c.SeedAccessCount[seedHash]
    
    execTime := c.SeedExecutionTime[seedHash]
    stats["exec_time_ms"] = execTime.Milliseconds()
    
    avgReward := c.CalculateSeedAverageReward(seedHash) // Internal RLock
    ucbScore := c.CalculateSeedUCB(seedHash)     // Internal RLock

    sumReward := c.SeedSumRewards[seedHash]
    rewardCount := c.SeedRewardCounts[seedHash]
    c.mu.RUnlock() // Unlock

    stats["sum_reward"] = sumReward
    stats["reward_count"] = rewardCount
    stats["avg_reward"] = avgReward
    stats["ucb_score"] = ucbScore
        
    return stats
}

// DumpAllStats exports all statistics
func (c *ClusterInfo) DumpAllStats() map[string]interface{} {

    c.mu.RLock()
    defer c.mu.RUnlock()

    stats := make(map[string]interface{})
    
    globalStats := make(map[string]interface{})
    globalStats["total_clusters"] = len(c.ClusterSizes)
    globalStats["total_seeds_in_map"] = len(c.SeedClusterMap) 
    globalStats["total_ucb_accesses"] = c.TotalAccess
    globalStats["total_coverage_points"] = c.TotalCoverage.Len()
    globalStats["exploration_rate_alpha"] = c.ExplorationRate
    stats["global"] = globalStats
    
    clusterStats := make(map[string]interface{})

    clusterIDs := make([]int, 0, len(c.ClusterSizes))
    for id := range c.ClusterSizes {
        clusterIDs = append(clusterIDs, id)
    }


    for _, clusterID := range clusterIDs { // Use copied ID list
        clusterStats[fmt.Sprintf("%d", clusterID)] = c.GetClusterStats(clusterID) // GetClusterStats internal will lock
    }
    stats["clusters"] = clusterStats
    
    seedStats := make(map[string]interface{})
    count := 0
    // Copy SeedAccessCount keys
    seedHashes := make([]string, 0, len(c.SeedAccessCount))
    for hash := range c.SeedAccessCount {
        seedHashes = append(seedHashes, hash)
    }

    for _, seedHash := range seedHashes {

        if c.SeedAccessCount[seedHash] > 0 && count < 10 { // Only show a few active seeds
            seedStats[seedHash] = c.GetSeedStats(seedHash)
            count++
        }
        if count >= 10 { break }
    }
    stats["top_accessed_seeds"] = seedStats
    
    return stats
}

// Lock, Unlock, RLock, RUnlock remain unchanged
func (ci *ClusterInfo) Lock() { ci.mu.Lock() }
func (ci *ClusterInfo) Unlock() { ci.mu.Unlock() }
func (ci *ClusterInfo) RLock() { ci.mu.RLock() }
func (ci *ClusterInfo) RUnlock() { ci.mu.RUnlock() }

// CleanupMemory periodically cleans up memory to prevent unlimited growth
func (c *ClusterInfo) CleanupMemory() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	
	// Check if cleanup is needed
	if now.Sub(c.lastMemoryCleanup) < c.cleanupInterval {
		return
	}

	log.Logf(1, "starting memory cleanup: seed entries=%d, coverage records=%d", len(c.SeedCoverageSize), len(c.CoverLastUpdate))

	// 1. Clean up seeds data that have not been accessed for a long time
	cutoffTime := now.Add(-2 * time.Hour) // 2 hours of data not accessed
	var removedSeeds []string

	for seedHash, lastUpdate := range c.CoverLastUpdate {
		if lastUpdate.Before(cutoffTime) {
			// Delete related all seed data
			delete(c.SeedCoverageSize, seedHash)
			delete(c.CoverLastUpdate, seedHash)
			delete(c.SeedExecutionTime, seedHash)
			delete(c.SeedBugCount, seedHash)
			delete(c.SeedSumRewards, seedHash)
			delete(c.SeedRewardCounts, seedHash)
			// Note: Do not delete SeedAccessCount and SeedClusterMap, as they are used for UCB calculation
			removedSeeds = append(removedSeeds, seedHash)
		}
	}

	// 2. If seed entries are still too many, clean up by access frequency
	if len(c.SeedCoverageSize) > c.maxSeedEntries {
		// Collect seeds with lowest access frequency
		type seedAccess struct {
			hash   string
			access int
		}
		var seedAccessList []seedAccess
		for seedHash := range c.SeedCoverageSize {
			access := c.SeedAccessCount[seedHash]
			seedAccessList = append(seedAccessList, seedAccess{hash: seedHash, access: access})
		}

		// Sort by access count, delete least accessed
		sort.Slice(seedAccessList, func(i, j int) bool {
			return seedAccessList[i].access < seedAccessList[j].access
		})

		numToRemove := len(c.SeedCoverageSize) - c.maxSeedEntries
		for i := 0; i < numToRemove && i < len(seedAccessList); i++ {
			seedHash := seedAccessList[i].hash
			delete(c.SeedCoverageSize, seedHash)
			delete(c.CoverLastUpdate, seedHash)
			delete(c.SeedExecutionTime, seedHash)
			delete(c.SeedBugCount, seedHash)
			delete(c.SeedSumRewards, seedHash)
			delete(c.SeedRewardCounts, seedHash)
			delete(c.SeedMutantCoverages, seedHash)
			delete(c.SeedMutantCrashes, seedHash)
			removedSeeds = append(removedSeeds, seedHash)
		}
	}

	// 3. Clean up empty or small clusters
	for clusterID, size := range c.ClusterSizes {
		if size <= 1 && clusterID != c.DefaultClusterID {
			// Move single seed to default cluster
			for seedHash, cID := range c.SeedClusterMap {
				if cID == clusterID {
					c.SeedClusterMap[seedHash] = c.DefaultClusterID
					c.ClusterSizes[c.DefaultClusterID]++
				}
			}
			for seedHash, cID := range c.ProgramHashes {
				if cID == clusterID {
					c.ProgramHashes[seedHash] = c.DefaultClusterID
				}
			}
			delete(c.ClusterSizes, clusterID)
			delete(c.ClusterSumRewards, clusterID)
			delete(c.ClusterRewardCounts, clusterID)
			delete(c.AccessCount, clusterID)
			delete(c.LastAccess, clusterID)
			delete(c.ClusterCenters, clusterID)
		}
	}

	// 4. Clean up EstimatedCovCache
	if len(c.EstimatedCovCache) > 1000 {
		// Simple empty, because this is estimated cache
		c.EstimatedCovCache = make(map[string]int)
	}

	// 5. Recalculate TotalClusterSize
	c.TotalClusterSize = 0
	for _, size := range c.ClusterSizes {
		c.TotalClusterSize += size
	}

	c.lastMemoryCleanup = now
	log.Logf(1, "memory cleanup completed: removed %d seed entries, current seed entries=%d, cluster count=%d", 
		len(removedSeeds), len(c.SeedCoverageSize), len(c.ClusterSizes))
}

// TryCleanupMemory attempts to clean up memory (non-blocking)
func (c *ClusterInfo) TryCleanupMemory() {
	// Check if cleanup is needed, avoid frequent locking
	c.mu.RLock()
	now := time.Now()
	needCleanup := now.Sub(c.lastMemoryCleanup) >= c.cleanupInterval
	c.mu.RUnlock()
	
	if needCleanup {
		c.CleanupMemory()
	}
}

// ChooseProgramFromMaxCPRCluster selects a random program from one of the highest CPR clusters.
func (c *ClusterInfo) ChooseProgramFromMaxCPRCluster(rnd *rand.Rand, corpusProgs []*prog.Prog, progToHash func(p *prog.Prog) string) *prog.Prog {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.ClusterSizes) == 0 || c.TotalClusterSize == 0 || len(corpusProgs) == 0 {
		log.Logf(2, "ChooseProgramFromMaxCPRCluster: Preconditions not met (ClusterSizes: %d, TotalClusterSize: %d, corpusProgs: %d)", len(c.ClusterSizes), c.TotalClusterSize, len(corpusProgs))
		if len(corpusProgs) > 0 {
			log.Logf(2, "ChooseProgramFromMaxCPRCluster: Fallback - returning random program from entire corpus due to unmet preconditions.")
			return corpusProgs[rnd.Intn(len(corpusProgs))]
		}
		return nil
	}

	maxCPR := -1.0
	var maxCPRClusters []int

	for clusterID, size := range c.ClusterSizes {
		if size == 0 { // Skip empty clusters
			continue
		}
		// Calculate CPR for this cluster
		density := float64(size) / float64(c.TotalClusterSize)
		if density == 0 {
			continue // Skip clusters with zero density
		}
		
		accessCount := float64(c.AccessCount[clusterID])
		cpr := (accessCount + 1.0) / density // CPR = (拉动次数 + 1) / 密度
		
		if cpr > maxCPR {
			maxCPR = cpr
			maxCPRClusters = []int{clusterID}
		} else if cpr == maxCPR {
			maxCPRClusters = append(maxCPRClusters, clusterID)
		}
	}

	if len(maxCPRClusters) == 0 {
		log.Logf(2, "ChooseProgramFromMaxCPRCluster: No maximum CPR clusters found.")
		if len(corpusProgs) > 0 {
			log.Logf(2, "ChooseProgramFromMaxCPRCluster: Fallback - returning random program from entire corpus as no max-CPR clusters found.")
			return corpusProgs[rnd.Intn(len(corpusProgs))]
		}
		return nil
	}

	selectedClusterID := maxCPRClusters[rnd.Intn(len(maxCPRClusters))]
	log.Logf(2, "ChooseProgramFromMaxCPRCluster: Selected max-CPR cluster ID: %d (CPR: %f)", selectedClusterID, maxCPR)

	// Optimized implementation: directly find from existing mapping, avoid creating large temporary map
	var progsInCluster []*prog.Prog
	
	// Only iterate over programs hash belonging to selected cluster
	for progHash, clID := range c.ProgramHashes {
		if clID == selectedClusterID {
			// Find corresponding program in corpusProgs (linear search, but only executed for selected cluster programs)
			for _, p := range corpusProgs {
				if p != nil && progToHash != nil && progToHash(p) == progHash {
					progsInCluster = append(progsInCluster, p)
					break // Exit inner loop when found
				}
			}
		}
	}
	
	log.Logf(2, "ChooseProgramFromMaxCPRCluster: Found %d programs in cluster %d from the current corpusProgs list.", len(progsInCluster), selectedClusterID)

	if len(progsInCluster) == 0 {
		log.Logf(2, "ChooseProgramFromMaxCPRCluster: No programs from corpusProgs found in selected max-CPR cluster %d.", selectedClusterID)
		if len(corpusProgs) > 0 {
			log.Logf(2, "ChooseProgramFromMaxCPRCluster: Fallback - returning random program from entire corpus as no programs found in selected cluster.")
			return corpusProgs[rnd.Intn(len(corpusProgs))]
		}
		return nil
	}

	return progsInCluster[rnd.Intn(len(progsInCluster))]
}