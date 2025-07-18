// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"context"
	"fmt"
	"maps"
	"math"
	"math/rand"
	"sync"
	"time"
	"sort"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

// Corpus object represents a set of syzkaller-found programs that
// cover the kernel up to the currently reached frontiers.
type Corpus struct {
	ctx      context.Context
	mu       sync.RWMutex
	progsMap map[string]*Item
	signal   signal.Signal // total signal of all items
	cover    cover.Cover   // total coverage of all items
	updates  chan<- NewItemEvent

	*ProgramsList
	StatProgs  *stat.Val
	StatSignal *stat.Val
	StatCover  *stat.Val

	focusAreas []*focusAreaState
}

type focusAreaState struct {
	FocusArea
	*ProgramsList
}

type FocusArea struct {
	Name     string // can be empty
	CoverPCs map[uint64]struct{}
	Weight   float64
}

func NewCorpus(ctx context.Context) *Corpus {
	return NewMonitoredCorpus(ctx, nil)
}

func NewMonitoredCorpus(ctx context.Context, updates chan<- NewItemEvent) *Corpus {
	return NewFocusedCorpus(ctx, updates, nil)
}

func NewFocusedCorpus(ctx context.Context, updates chan<- NewItemEvent, areas []FocusArea) *Corpus {
	corpus := &Corpus{
		ctx:          ctx,
		progsMap:     make(map[string]*Item),
		updates:      updates,
		ProgramsList: &ProgramsList{},
	}
	corpus.StatProgs = stat.New("corpus", "Number of test programs in the corpus", stat.Console,
		stat.Link("/corpus"), stat.Graph("corpus"), stat.LenOf(&corpus.progsMap, &corpus.mu))
	corpus.StatSignal = stat.New("signal", "Fuzzing signal in the corpus",
		stat.LenOf(&corpus.signal, &corpus.mu))
	corpus.StatCover = stat.New("coverage", "Source coverage in the corpus", stat.Console,
		stat.Link("/cover"), stat.Prometheus("syz_corpus_cover"), stat.LenOf(&corpus.cover, &corpus.mu))
	for _, area := range areas {
		obj := &ProgramsList{}
		if len(areas) > 1 && area.Name != "" {
			// Only show extra statistics if there's more than one area.
			stat.New("corpus ["+area.Name+"]",
				fmt.Sprintf("Corpus programs of the focus area %q", area.Name),
				stat.Console, stat.Graph("corpus"),
				stat.LenOf(&obj.progs, &corpus.mu))
		}
		corpus.focusAreas = append(corpus.focusAreas, &focusAreaState{
			FocusArea:    area,
			ProgramsList: obj,
		})
	}
	return corpus
}

// It may happen that a single program is relevant because of several
// sysalls. In that case, there will be several ItemUpdate entities.
type ItemUpdate struct {
	Call     int
	RawCover []uint64
}

// Item objects are to be treated as immutable, otherwise it's just
// too hard to synchonize accesses to them across the whole project.
// When Corpus updates one of its items, it saves a copy of it.
type Item struct {
	Sig     string
	Call    int
	Prog    *prog.Prog
	HasAny  bool // whether the prog contains squashed arguments
	Signal  signal.Signal
	Cover   []uint64
	Updates []ItemUpdate

	areas map[*focusAreaState]struct{}
}

func (item Item) StringCall() string {
	return item.Prog.CallName(item.Call)
}

type NewInput struct {
	Prog     *prog.Prog
	Call     int
	Signal   signal.Signal
	Cover    []uint64
	RawCover []uint64
}

type NewItemEvent struct {
	Sig      string
	Exists   bool
	ProgData []byte
	NewCover []uint64
}

func (corpus *Corpus) Save(inp NewInput) {
	progData := inp.Prog.Serialize()
	sig := hash.String(progData)

	corpus.mu.Lock()
	defer corpus.mu.Unlock()

	update := ItemUpdate{
		Call:     inp.Call,
		RawCover: inp.RawCover,
	}
	exists := false
	if old, ok := corpus.progsMap[sig]; ok {
		exists = true
		newSignal := old.Signal.Copy()
		newSignal.Merge(inp.Signal)
		var newCover cover.Cover
		newCover.Merge(old.Cover)
		newCover.Merge(inp.Cover)
		newItem := &Item{
			Sig:     sig,
			Prog:    old.Prog,
			Call:    old.Call,
			HasAny:  old.HasAny,
			Signal:  newSignal,
			Cover:   newCover.Serialize(),
			Updates: append([]ItemUpdate{}, old.Updates...),
			areas:   maps.Clone(old.areas),
		}
		const maxUpdates = 32
		if len(newItem.Updates) < maxUpdates {
			newItem.Updates = append(newItem.Updates, update)
		}
		corpus.progsMap[sig] = newItem
		corpus.applyFocusAreas(newItem, inp.Cover)
	} else {
		item := &Item{
			Sig:     sig,
			Call:    inp.Call,
			Prog:    inp.Prog,
			HasAny:  inp.Prog.ContainsAny(),
			Signal:  inp.Signal,
			Cover:   inp.Cover,
			Updates: []ItemUpdate{update},
		}
		corpus.progsMap[sig] = item
		corpus.applyFocusAreas(item, inp.Cover)
		corpus.saveProgram(inp.Prog, inp.Signal)
	}
	corpus.signal.Merge(inp.Signal)
	newCover := corpus.cover.MergeDiff(inp.Cover)
	if corpus.updates != nil {
		select {
		case <-corpus.ctx.Done():
		case corpus.updates <- NewItemEvent{
			Sig:      sig,
			Exists:   exists,
			ProgData: progData,
			NewCover: newCover,
		}:
		}
	}
}

func (corpus *Corpus) applyFocusAreas(item *Item, coverDelta []uint64) {
	for _, area := range corpus.focusAreas {
		matches := false
		for _, pc := range coverDelta {
			if _, ok := area.CoverPCs[pc]; ok {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		area.saveProgram(item.Prog, item.Signal)
		if item.areas == nil {
			item.areas = make(map[*focusAreaState]struct{})
			item.areas[area] = struct{}{}
		}
	}
}

func (corpus *Corpus) Signal() signal.Signal {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.signal.Copy()
}

func (corpus *Corpus) Items() []*Item {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	ret := make([]*Item, 0, len(corpus.progsMap))
	for _, item := range corpus.progsMap {
		ret = append(ret, item)
	}
	return ret
}

func (corpus *Corpus) Item(sig string) *Item {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.progsMap[sig]
}

type CallCov struct {
	Count int
	Cover cover.Cover
}

func (corpus *Corpus) CallCover() map[string]*CallCov {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	calls := make(map[string]*CallCov)
	for _, inp := range corpus.progsMap {
		call := inp.StringCall()
		if calls[call] == nil {
			calls[call] = new(CallCov)
		}
		cc := calls[call]
		cc.Count++
		cc.Cover.Merge(inp.Cover)
	}
	return calls
}

// GetProgHash returns the hash string of a program
func GetProgHash(p *prog.Prog) string {
	return hash.String(p.Serialize())
}


func recordAccess(ClusterInfo *ClusterInfo, hash string) {
    ClusterInfo.mu.Lock()
    defer ClusterInfo.mu.Unlock()
    
    ClusterInfo.SeedAccessCount[hash]++ // Increase seed access count
    
    clusterID, exists := ClusterInfo.SeedClusterMap[hash]
    if !exists {
        clusterID, exists = ClusterInfo.ProgramHashes[hash]
        if !exists {
            // log.Logf(0, "recordAccess: Seed %s has no clusterID, cannot update cluster access count.", hash[:8])
            return // or assign default cluster
        }
        ClusterInfo.SeedClusterMap[hash] = clusterID
    }
    
    ClusterInfo.AccessCount[clusterID]++ // Increase cluster access count
    ClusterInfo.LastAccess[clusterID] = time.Now()
    ClusterInfo.TotalAccess++ // Increase total access count
}

// Declare a package-level debug flag variable
var developerDebugMode = true 



// Helper struct for sorting cluster scores
type clusterScorePair struct {
	ID    int
	Score float64
	Size  int
	// Add other fields if needed for richer logging of ranked list
}


func (c *Corpus) ChooseProgramCommunityUCB(rnd *rand.Rand, ClusterInfo *ClusterInfo) *prog.Prog {
	items := c.Items()
	if len(items) == 0 {
		return nil
	}
	if ClusterInfo == nil {
		log.Logf(0, "ChooseProgramCommunityUCB: ClusterInfo is nil, falling back to ChooseProgram")
		return c.ChooseProgram(rnd)
	}

	resultCh := make(chan *prog.Prog, 1)
	timeoutCh := time.After(15 * time.Second) // Keep timeout

	go func() {
		// --- Step 1: Build cluster-to-program mapping and copy necessary data to reduce lock contention ---
		clusterPrograms := make(map[int][]*Item) // Maps clusterID to list of Items in that cluster

		// Local copies of data from ClusterInfo
		var seedClusterMapLocal map[string]int
		var programHashesLocal map[string]int
		var totalClusterSizeLocal int
		var totalAccessLocal int // Total UCB selections made
		var clusterExploreCoefLocal float64
		var seedExploreCoefLocal float64
		var clusterSizesLocal map[int]int
		var accessCountsLocal map[int]int // n_Ci(t) - times cluster Ci was chosen

		var clusterSumRewardsLocal map[int]float64
		var clusterRewardCountsLocal map[int]int
		var seedSumRewardsLocal map[string]float64
		var seedRewardCountsLocal map[string]int

		var seedCoverageSizeLocal map[string]int
		var seedExecutionTimeLocal map[string]time.Duration
		var seedBugCountLocal map[string]int
		var seedAccessCountLocal map[string]int // n_Sij(t) - times seed Sij was chosen
		var seedMutantCoveragesLocal map[string][]int // Track mutant offspring coverages
		var seedMutantCrashesLocal map[string][]int   // Track mutant offspring crashes

		ClusterInfo.RLock()
		// Copy maps and values needed
		seedClusterMapLocal = make(map[string]int, len(ClusterInfo.SeedClusterMap))
		for k, v := range ClusterInfo.SeedClusterMap {
			seedClusterMapLocal[k] = v
		}
		programHashesLocal = make(map[string]int, len(ClusterInfo.ProgramHashes))
		for k, v := range ClusterInfo.ProgramHashes {
			programHashesLocal[k] = v
		}

		totalClusterSizeLocal = ClusterInfo.TotalClusterSize
		totalAccessLocal = ClusterInfo.TotalAccess // This is total UCB selections, updated by recordAccess
		clusterExploreCoefLocal = ClusterInfo.ClusterExploreCoef
		seedExploreCoefLocal = ClusterInfo.SeedExploreCoef

		clusterSizesLocal = make(map[int]int, len(ClusterInfo.ClusterSizes))
		for k, v := range ClusterInfo.ClusterSizes {
			clusterSizesLocal[k] = v
		}
		accessCountsLocal = make(map[int]int, len(ClusterInfo.AccessCount)) // n_Ci(t)
		for k, v := range ClusterInfo.AccessCount {
			accessCountsLocal[k] = v
		}

		clusterSumRewardsLocal = make(map[int]float64, len(ClusterInfo.ClusterSumRewards))
		for k, v := range ClusterInfo.ClusterSumRewards {
			clusterSumRewardsLocal[k] = v
		}
		clusterRewardCountsLocal = make(map[int]int, len(ClusterInfo.ClusterRewardCounts))
		for k, v := range ClusterInfo.ClusterRewardCounts {
			clusterRewardCountsLocal[k] = v
		}

		seedSumRewardsLocal = make(map[string]float64, len(ClusterInfo.SeedSumRewards))
		for k, v := range ClusterInfo.SeedSumRewards {
			seedSumRewardsLocal[k] = v
		}
		seedRewardCountsLocal = make(map[string]int, len(ClusterInfo.SeedRewardCounts))
		for k, v := range ClusterInfo.SeedRewardCounts {
			seedRewardCountsLocal[k] = v
		}

		seedCoverageSizeLocal = make(map[string]int, len(ClusterInfo.SeedCoverageSize))
		for k, v := range ClusterInfo.SeedCoverageSize {
			seedCoverageSizeLocal[k] = v
		}
		seedExecutionTimeLocal = make(map[string]time.Duration, len(ClusterInfo.SeedExecutionTime))
		for k, v := range ClusterInfo.SeedExecutionTime {
			seedExecutionTimeLocal[k] = v
		}
		seedBugCountLocal = make(map[string]int, len(ClusterInfo.SeedBugCount))
		for k, v := range ClusterInfo.SeedBugCount {
			seedBugCountLocal[k] = v
		}
		seedAccessCountLocal = make(map[string]int, len(ClusterInfo.SeedAccessCount)) // n_Sij(t)
		for k, v := range ClusterInfo.SeedAccessCount {
			seedAccessCountLocal[k] = v
		}
		
		// Copy new fields for mutant offspring tracking
		seedMutantCoveragesLocal = make(map[string][]int, len(ClusterInfo.SeedMutantCoverages))
		for k, v := range ClusterInfo.SeedMutantCoverages {
			seedMutantCoveragesLocal[k] = append([]int{}, v...) // Deep copy slice
		}
		seedMutantCrashesLocal = make(map[string][]int, len(ClusterInfo.SeedMutantCrashes))
		for k, v := range ClusterInfo.SeedMutantCrashes {
			seedMutantCrashesLocal[k] = append([]int{}, v...) // Deep copy slice
		}
		
		ClusterInfo.RUnlock()

		// Classify programs by cluster and handle assignment of new seeds/clusters
		for _, item := range items {
			hash := GetProgHash(item.Prog)
			var clusterID int
			var clusterKnown bool

			if id, ok := seedClusterMapLocal[hash]; ok {
				clusterID = id
				clusterKnown = true
			} else if id, ok := programHashesLocal[hash]; ok { // Fallback for progs not yet in SeedClusterMap
				clusterID = id
				clusterKnown = true
				seedClusterMapLocal[hash] = id // Update local copy
			}

			if !clusterKnown {
				ClusterInfo.Lock()
				var currentExists bool
				clusterID, currentExists = ClusterInfo.GetClusterID(hash)

				if !currentExists {
					var newClusterCreated bool
					clusterID, newClusterCreated = ClusterInfo.AssignCluster(item.Prog, hash)

					programHashesLocal[hash] = clusterID
					seedClusterMapLocal[hash] = clusterID
					clusterSizesLocal[clusterID] = ClusterInfo.ClusterSizes[clusterID] // Get updated size
					if newClusterCreated {
						totalClusterSizeLocal = ClusterInfo.TotalClusterSize
						log.Logf(0, "ChooseProgramCommunityUCB: Prog %s created new cluster %d", hash[:8], clusterID)
					} else {
						totalClusterSizeLocal = ClusterInfo.TotalClusterSize // Ensure local total is fresh
					}
				} else {
					programHashesLocal[hash] = clusterID
					seedClusterMapLocal[hash] = clusterID
				}
				ClusterInfo.Unlock()
			}
			if _, ok := clusterPrograms[clusterID]; !ok {
				clusterPrograms[clusterID] = []*Item{}
			}
			clusterPrograms[clusterID] = append(clusterPrograms[clusterID], item)
		}

		if len(clusterSizesLocal) > 0 && totalClusterSizeLocal == 0 {
			currentTotal := 0
			for _, s := range clusterSizesLocal {
				currentTotal += s
			}
			totalClusterSizeLocal = currentTotal
			if totalClusterSizeLocal == 0 {
				totalClusterSizeLocal = 1
			} // Avoid div by zero
		}

		// --- Step 2: Calculate UCB scores for all clusters ---
		allClusterScores := make(map[int]float64)
		clusterAvgRewards := make(map[int]float64) // Store average rewards for logging

		for clusterID, progsInCluster := range clusterPrograms {
			if len(progsInCluster) == 0 {
				continue
			}

			var avgRewardCluster float64
			currentClusterSize := clusterSizesLocal[clusterID]
			
			// 修改后的社区奖励计算：现有种子的覆盖率均值 × (1 + 平均crash)
			if currentClusterSize > 0 {
				var sumCovSijInCluster float64
				var sumCrashesInCluster int
				var seedsActualInClusterForAvg int
				
				for sHash, cID := range seedClusterMapLocal {
					if cID == clusterID {
						seedsActualInClusterForAvg++
						sumCovSijInCluster += float64(seedCoverageSizeLocal[sHash])
						sumCrashesInCluster += seedBugCountLocal[sHash]
					}
				}

				avgCovInCluster := 0.0
				if seedsActualInClusterForAvg > 0 {
					avgCovInCluster = sumCovSijInCluster / float64(seedsActualInClusterForAvg)
				}
				
				avgCrashInCluster := 0.0
				if seedsActualInClusterForAvg > 0 {
					avgCrashInCluster = float64(sumCrashesInCluster) / float64(seedsActualInClusterForAvg)
				}

				// 新的社区奖励公式：覆盖率均值 × (1 + 平均crash)
				avgRewardCluster = avgCovInCluster * (1.0 + avgCrashInCluster)
			} else {
				avgRewardCluster = 0.0
			}
			clusterAvgRewards[clusterID] = avgRewardCluster // Store for later logging if needed

			clusterSelections_nCi_t := float64(accessCountsLocal[clusterID] + 1)
			exploreTermCluster := clusterExploreCoefLocal * math.Sqrt((2.0*math.Log(float64(totalAccessLocal+1)))/clusterSelections_nCi_t)

			clusterScore := avgRewardCluster + exploreTermCluster
			allClusterScores[clusterID] = clusterScore


		}

		if len(allClusterScores) == 0 {
			log.Logf(0, "ChooseProgramCommunityUCB: No cluster scores, falling back to random from all items.")
			if len(items) == 0 {
				resultCh <- nil
				return
			}
			idx := rnd.Intn(len(items))
			selectedProg := items[idx].Prog
			go recordAccess(ClusterInfo, GetProgHash(selectedProg))
			resultCh <- selectedProg
			return
		}

		// LOGGING POINT 2: Log ranked list of all clusters
		sortedClusterScores := make([]clusterScorePair, 0, len(allClusterScores))
		for id, score := range allClusterScores {
			sortedClusterScores = append(sortedClusterScores, clusterScorePair{ID: id, Score: score, Size: clusterSizesLocal[id]})
		}
		sort.Slice(sortedClusterScores, func(i, j int) bool {
			return sortedClusterScores[i].Score > sortedClusterScores[j].Score
		})


		var selectedClusterID int

		highestScoreClusters := []int{}
		actualHighestScore := math.Inf(-1)
		if len(sortedClusterScores) > 0 {
			actualHighestScore = sortedClusterScores[0].Score
			for _, p := range sortedClusterScores {
				if p.Score == actualHighestScore {
					highestScoreClusters = append(highestScoreClusters, p.ID)
				} else if p.Score < actualHighestScore {
					break
				}
			}
		}

		secondHighestScoreClusters := []int{}
		actualSecondHighestScore := math.Inf(-1)
		if len(sortedClusterScores) > len(highestScoreClusters) { // Must have at least one non-highest score cluster
			startIndexForSecond := len(highestScoreClusters)
			actualSecondHighestScore = sortedClusterScores[startIndexForSecond].Score
			for i := startIndexForSecond; i < len(sortedClusterScores); i++ {
				p := sortedClusterScores[i]
				if p.Score == actualSecondHighestScore {
					secondHighestScoreClusters = append(secondHighestScoreClusters, p.ID)
				} else if p.Score < actualSecondHighestScore {
					break
				}
			}
		}

		prob := rnd.Float64()

		if len(highestScoreClusters) == 0 { 
			if len(items) == 0 { resultCh <- nil; return }
			idx := rnd.Intn(len(items)); progToReturn := items[idx].Prog
			go recordAccess(ClusterInfo, GetProgHash(progToReturn))
			resultCh <- progToReturn; return
		}


		if prob < 0.90 {
			// 90% choose highest score cluster
			//selectionStrategy = "Highest UCB Score (90%)"
			selectedClusterID = highestScoreClusters[rnd.Intn(len(highestScoreClusters))]
			//chosenClusterScoreForLog = actualHighestScore
		} else if prob < 0.95 { 
			// 5% choose second highest score cluster
			if len(secondHighestScoreClusters) > 0 {
				//selectionStrategy = "Second Highest UCB Score (5%)"
				selectedClusterID = secondHighestScoreClusters[rnd.Intn(len(secondHighestScoreClusters))]
				//chosenClusterScoreForLog = actualSecondHighestScore
			} else {
				//selectionStrategy = "Second Highest UCB Score (Fallback to Highest, 5%)"
				selectedClusterID = highestScoreClusters[rnd.Intn(len(highestScoreClusters))]
				//chosenClusterScoreForLog = actualHighestScore
			}
		} else {
			// 5% randomly choose a cluster
			//selectionStrategy = "Random Cluster (5%)"
			allClusterIDsForRandom := make([]int, 0, len(allClusterScores))
			for id := range allClusterScores {
				allClusterIDsForRandom = append(allClusterIDsForRandom, id)
			}
			selectedClusterID = allClusterIDsForRandom[rnd.Intn(len(allClusterIDsForRandom))]
			//chosenClusterScoreForLog = allClusterScores[selectedClusterID]
		}

		currentClusterProgs := clusterPrograms[selectedClusterID]

		if len(currentClusterProgs) == 0 {
			// log.Logf(2, "ChooseProgramCommunityUCB: Selected cluster %d (via %s) is empty, falling back to random from all items.",
			// 	selectedClusterID, selectionStrategy)
			if len(items) == 0 {
				resultCh <- nil
				return
			}
			idx := rnd.Intn(len(items))
			selectedProg := items[idx].Prog
			go recordAccess(ClusterInfo, GetProgHash(selectedProg))
			resultCh <- selectedProg
			return
		}

		// --- Step 3: Use seed-level UCB to select the best program from the selected cluster (Formula 9) ---
		bestSeedScore := math.Inf(-1)
		var bestSeeds []*prog.Prog
		seedAvgRewardsMap := make(map[string]float64) // To store avgRewardSeed for final logging

		// log.Logf(0, "--- Seeds in Selected Cluster %d ---", selectedClusterID) // Can uncomment for more detailed logs
		for _, item := range currentClusterProgs {
			seedHash := GetProgHash(item.Prog)

			var avgRewardSeed float64
			
			// 修改后的种子奖励计算：突变后代种子的覆盖率均值 × (1 + 平均crash)
			mutantCoverages := seedMutantCoveragesLocal[seedHash]
			mutantCrashes := seedMutantCrashesLocal[seedHash]
			
			if len(mutantCoverages) > 0 && len(mutantCrashes) > 0 {
				// 计算突变后代的覆盖率均值
				totalCoverage := 0
				for _, cov := range mutantCoverages {
					totalCoverage += cov
				}
				avgCoverageOfMutants := float64(totalCoverage) / float64(len(mutantCoverages))
				
				// 计算突变后代的平均crash
				totalCrashes := 0
				for _, crash := range mutantCrashes {
					totalCrashes += crash
				}
				avgCrashOfMutants := float64(totalCrashes) / float64(len(mutantCrashes))
				
				// 新的种子奖励公式：突变后代覆盖率均值 × (1 + 平均crash)
				avgRewardSeed = avgCoverageOfMutants * (1.0 + avgCrashOfMutants)
			} else {
				// 如果没有突变后代数据，使用种子自身的覆盖率作为初始奖励
				currentSeedCovSize := float64(seedCoverageSizeLocal[seedHash])
				if currentSeedCovSize > 0 {
					avgRewardSeed = currentSeedCovSize * (1.0 + float64(seedBugCountLocal[seedHash]))
				} else {
					avgRewardSeed = 1.0 // 默认最小奖励
				}
			}
			seedAvgRewardsMap[seedHash] = avgRewardSeed // Store for final selected seed log

			seedSelections_nSij_t := float64(seedAccessCountLocal[seedHash] + 1)
			exploreTermSeed := seedExploreCoefLocal * math.Sqrt((2.0*math.Log(float64(totalAccessLocal+1)))/seedSelections_nSij_t)

			seedScore := avgRewardSeed + exploreTermSeed


			if seedScore > bestSeedScore {
				bestSeedScore = seedScore
				bestSeeds = []*prog.Prog{item.Prog}
			} else if seedScore == bestSeedScore {
				bestSeeds = append(bestSeeds, item.Prog)
			}
		}
		// log.Logf(0, "--- End Seeds in Cluster %d ---", selectedClusterID) // Can uncomment

		if len(bestSeeds) == 0 {
			log.Logf(0, "ChooseProgramCommunityUCB: No best seeds in cluster %d, choosing randomly from cluster.", selectedClusterID)
			if len(currentClusterProgs) == 0 { // Should not happen given previous checks
				resultCh <- nil
				return
			}
			idx := rnd.Intn(len(currentClusterProgs))
			selectedProg := currentClusterProgs[idx].Prog
			go recordAccess(ClusterInfo, GetProgHash(selectedProg))
			resultCh <- selectedProg
			return
		}
		selectedProg := bestSeeds[rnd.Intn(len(bestSeeds))]
		selectedSeedHash := GetProgHash(selectedProg)

		go recordAccess(ClusterInfo, selectedSeedHash)
		resultCh <- selectedProg

	}() // End of main goroutine for UCB calculation

	select {
	case prog := <-resultCh:
		return prog
	case <-timeoutCh:
		log.Logf(2, "ChooseProgramCommunityUCB: UCB selection TIMEOUT, falling back to random choice from all items.")
		if len(items) == 0 {
			return nil
		}
		idx := rnd.Intn(len(items))
		prog := items[idx].Prog
		go recordAccess(ClusterInfo, GetProgHash(prog))
		return prog
	}
}

