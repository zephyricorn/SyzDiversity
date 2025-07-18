// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	
	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

type Fuzzer struct {
	Stats
	Config *Config
	Cover  *Cover

	ctx          context.Context
	mu           sync.Mutex
	rnd          *rand.Rand
	target       *prog.Target
	hintsLimiter prog.HintsLimiter
	runningJobs  map[jobIntrospector]struct{}

	ct           *prog.ChoiceTable
	ctProgs      int
	ctMu         sync.Mutex // TODO: use RWLock.
	ctRegenerate chan struct{}
	ClusterInfo  *corpus.ClusterInfo // New field
	startTime    time.Time           

	// UCB data update worker pool
	ucbUpdateChan chan ucbUpdateTask
	ucbWorkerDone chan struct{}

	execQueues
}

// Add new type definitions before Fuzzer struct definition
type ClusterDensityPair struct {
	ID   int
	Size int
}

type ClusterCPRPair struct {
	ID  int
	CPR float64
}

// UCB update task type
type ucbUpdateTask struct {
	hash         string
	rawCover     []uint64
	execTime     time.Duration
	bugCount     int
	isFromCorpus bool
	prog         *prog.Prog
}

func NewFuzzer(ctx context.Context, cfg *Config, rnd *rand.Rand,
	target *prog.Target) *Fuzzer {
	if cfg.NewInputFilter == nil {
		cfg.NewInputFilter = func(call string) bool {
			return true
		}
	}
	
	// Initialize default long-term strategy configuration
	initializeLongTermConfig(cfg)
	f := &Fuzzer{
		Stats:       newStats(target),
		Config:      cfg,
		Cover:       newCover(),
		ClusterInfo: cfg.ClusterInfo,
		startTime:   time.Now(), // Initialize start time

		ctx:         ctx,
		rnd:         rnd,
		target:      target,
		runningJobs: map[jobIntrospector]struct{}{},

		// We're okay to lose some of the messages -- if we are already
		// regenerating the table, we don't want to repeat it right away.
		ctRegenerate: make(chan struct{}),

		// Initialize UCB worker pool
		ucbUpdateChan: make(chan ucbUpdateTask, 1000), // Buffer 1000 tasks
		ucbWorkerDone: make(chan struct{}),
	}
	f.execQueues = newExecQueues(f)
	// Initialize ClusterInfo
	f.initClusterInfo(cfg)

	f.updateChoiceTable(nil)
	// Add cluster information
	f.ClusterInfo = cfg.ClusterInfo
	go f.choiceTableUpdater()
	if cfg.Debug {
		go f.logCurrentStats()
	}

	// Start UCB data update worker (use fixed number of workers to control concurrency)
	go f.ucbUpdateWorker()

	// Start priority update thread
	if f.ClusterInfo != nil && f.candidateQueue != nil {
		f.Logf(0, "Priority updater will start in 2 minutes")
		// Use time.AfterFunc to start priority update after 2 minutes
		// Start priority update thread in 2 minutes
		go f.updateCandidateQueuePriority()
	} else {
		f.Logf(0, "warning: conditions not met for starting priority updater")
	}

	// Start cluster info save thread
	if f.ClusterInfo != nil {
		go f.periodicSaveClusterInfo()
	}

	return f
}

type execQueues struct {
	triageCandidateQueue *queue.DynamicOrderer
	candidateQueue       *queue.PlainQueue
	triageQueue          *queue.DynamicOrderer
	smashQueue           *queue.PlainQueue
	source               queue.Source
}

func newExecQueues(fuzzer *Fuzzer) execQueues {
	ret := execQueues{
		triageCandidateQueue: queue.DynamicOrder(),
		candidateQueue:       queue.Plain(),
		triageQueue:          queue.DynamicOrder(),
		smashQueue:           queue.Plain(),
	}
	// Alternate smash jobs with exec/fuzz to spread attention to the wider area.
	skipQueue := 3
	if fuzzer.Config.PatchTest {
		// When we do patch fuzzing, we do not focus on finding and persisting
		// new coverage that much, so it's reasonable to spend more time just
		// mutating various corpus programs.
		skipQueue = 2
	}
	// Sources are listed in the order, in which they will be polled.
	ret.source = queue.Order(
		ret.triageCandidateQueue,
		ret.candidateQueue,
		ret.triageQueue,
		queue.Alternate(ret.smashQueue, skipQueue),
		queue.Callback(fuzzer.genFuzz),
	)
	return ret
}

func (fuzzer *Fuzzer) CandidateTriageFinished() bool {
	return fuzzer.statCandidates.Val()+fuzzer.statJobsTriageCandidate.Val() == 0
}

func (fuzzer *Fuzzer) execute(executor queue.Executor, req *queue.Request) *queue.Result {
	return fuzzer.executeWithFlags(executor, req, 0)
}

func (fuzzer *Fuzzer) executeWithFlags(executor queue.Executor, req *queue.Request, flags ProgFlags) *queue.Result {
	fuzzer.enqueue(executor, req, flags, 0)
	return req.Wait(fuzzer.ctx)
}

func (fuzzer *Fuzzer) prepare(req *queue.Request, flags ProgFlags, attempt int) {
	req.OnDone(func(req *queue.Request, res *queue.Result) bool {
		return fuzzer.processResult(req, res, flags, attempt)
	})
}

func (fuzzer *Fuzzer) enqueue(executor queue.Executor, req *queue.Request, flags ProgFlags, attempt int) {
	fuzzer.prepare(req, flags, attempt)
	executor.Submit(req)
}

// processResult (V1 - Modified for Memory Optimization and Δcov)
func (fuzzer *Fuzzer) processResult(req *queue.Request, res *queue.Result, flags ProgFlags, attempt int) bool {
	// --- START: Default syzkaller processResult triage logic ---
	dontTriage := flags&progInTriage > 0 || res.Status == queue.Hanged
	var triage map[int]*triageCall 
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal > 0 && res.Info != nil && !dontTriage {
		for callIdx, info := range res.Info.Calls {
			fuzzer.triageProgCall(req.Prog, info, callIdx, &triage)
		}
		fuzzer.triageProgCall(req.Prog, res.Info.Extra, -1, &triage)

		if len(triage) != 0 {
			queueForJob, statForJob := fuzzer.triageQueue, fuzzer.statJobsTriage
			if flags&progCandidate > 0 {
				queueForJob, statForJob = fuzzer.triageCandidateQueue, fuzzer.statJobsTriageCandidate
			}
			job := &triageJob{ 
				p:        req.Prog.Clone(),
				executor: res.Executor, 
				flags:    flags,
				queue:    queueForJob.Append(),
				calls:    triage,
				info: &JobInfo{ 
					Name: req.Prog.String(),
					Type: "triage",
				},
			}
			for id := range triage {
				job.info.Calls = append(job.info.Calls, job.p.CallName(id))
			}
			sort.Strings(job.info.Calls)
			fuzzer.startJob(statForJob, job)
		}
	}
	// --- END: Default syzkaller processResult triage logic ---

	if res.Info != nil {
		// --- START: Default syzkaller processResult stat and call info handling ---
		fuzzer.statExecTime.Add(int(res.Info.Elapsed / 1e6))
		for call, info := range res.Info.Calls {
			fuzzer.handleCallInfo(req, info, call)
		}
		fuzzer.handleCallInfo(req, res.Info.Extra, -1)
		// --- END: Default syzkaller processResult stat and call info handling ---

		// --- START: UCB related updates (Authoritative updates here) ---
		if fuzzer.ClusterInfo != nil && req.Prog != nil {
			// MODYFIKACJA: Usuwamy pole 'prio' z tej struktury
			progDataForClusterUpdate := struct {
				hash         string
				rawCover     []uint64
				execTime     time.Duration
				bugCount     int
				isFromCorpus bool
				prog         *prog.Prog
			}{
				hash:         GetProgHash(req.Prog), // GetProgHash powinno być zdefiniowane gdzie indziej
				execTime:     time.Duration(res.Info.Elapsed),
				isFromCorpus: (flags & ProgFromCorpus != 0),
				prog:         req.Prog,
				// prio: req.ExecOpts.ProgPrio(), // <<< USUWAMY tę linię (ok. 221)
			}

			for _, callInfo := range res.Info.Calls {
				if callInfo != nil && callInfo.Cover != nil {
					progDataForClusterUpdate.rawCover = append(progDataForClusterUpdate.rawCover, callInfo.Cover...)
				}
			}
			if res.Info.Extra != nil && res.Info.Extra.Cover != nil {
				progDataForClusterUpdate.rawCover = append(progDataForClusterUpdate.rawCover, res.Info.Extra.Cover...)
			}

			if res.Status == queue.Crashed {
				progDataForClusterUpdate.bugCount = 1
			} else {
				for _, call := range res.Info.Calls {
					if call != nil && call.Error != 0 {
						progDataForClusterUpdate.bugCount++
					}
				}
			}

			if len(progDataForClusterUpdate.rawCover) > 0 || progDataForClusterUpdate.bugCount > 0 || progDataForClusterUpdate.isFromCorpus {
				
				task := ucbUpdateTask{
					hash:         progDataForClusterUpdate.hash,
					rawCover:     progDataForClusterUpdate.rawCover,
					execTime:     progDataForClusterUpdate.execTime,
					bugCount:     progDataForClusterUpdate.bugCount,
					isFromCorpus: progDataForClusterUpdate.isFromCorpus,
					prog:         progDataForClusterUpdate.prog,
				}
				
				select {
				case fuzzer.ucbUpdateChan <- task:
				default:
					if fuzzer.Config.Debug {
						fuzzer.Logf(1, "UCB worker pool full, dropping update for prog %s", progDataForClusterUpdate.hash[:8])
					}
				}
				
				// 新增：如果当前程序是突变产生的，记录突变后代的信息到原始种子
				if req.OriginSeedHash != "" && !req.IsGenerated {
					// 直接更新原始种子的突变后代信息
					if fuzzer.ClusterInfo != nil {
						ci := fuzzer.ClusterInfo
						ci.Lock()
						
						// 确保map已初始化
						if ci.SeedMutantCoverages == nil {
							ci.SeedMutantCoverages = make(map[string][]int)
						}
						if ci.SeedMutantCrashes == nil {
							ci.SeedMutantCrashes = make(map[string][]int)
						}
						
						// 记录突变后代的覆盖率
						mutantCoverageSize := len(progDataForClusterUpdate.rawCover)
						ci.SeedMutantCoverages[req.OriginSeedHash] = append(ci.SeedMutantCoverages[req.OriginSeedHash], mutantCoverageSize)
						
						// 记录突变后代的crash情况
						ci.SeedMutantCrashes[req.OriginSeedHash] = append(ci.SeedMutantCrashes[req.OriginSeedHash], progDataForClusterUpdate.bugCount)
						
						ci.Unlock()
						
						if fuzzer.Config.Debug {
							fuzzer.Logf(2, "Recorded mutant offspring for seed %s: coverage=%d, crashes=%d", 
								req.OriginSeedHash[:8], mutantCoverageSize, progDataForClusterUpdate.bugCount)
						}
					}
				}
			}
		}
	}
	// --- END: UCB related updates ---

	// --- START: Default syzkaller processResult candidate re-queue and stat update ---
	maxCandidateAttempts := 3
	if req.Risky() {
		maxCandidateAttempts = 2
		if fuzzer.Config.Snapshot || res.Status == queue.Hanged {
			maxCandidateAttempts = 0
		}
	}
	if len(triage) == 0 && flags&ProgFromCorpus != 0 && attempt < maxCandidateAttempts {
		fuzzer.enqueue(fuzzer.candidateQueue, req, flags, attempt+1)
		return false
	}
	if flags&progCandidate != 0 {
		fuzzer.statCandidates.Add(-1)
	}
	return true
	// --- END: Default syzkaller processResult candidate re-queue and stat update ---
}

type Config struct {
	Debug                      bool
	Corpus                     *corpus.Corpus
	Logf                       func(level int, msg string, args ...interface{})
	Snapshot                   bool
	Coverage                   bool
	FaultInjection             bool
	Comparisons                bool
	Collide                    bool
	EnabledCalls               map[*prog.Syscall]bool
	NoMutateCalls              map[int]bool
	FetchRawCover              bool
	NewInputFilter             func(call string) bool
	PatchTest                  bool
	Workdir                    string              // Working directory
	ClusterInfo                *corpus.ClusterInfo // Cluster information
	ClusterSimilarityThreshold float64             // Cluster similarity threshold
	
	// Long-term strategy configuration (for runtime > 4 hours)
	// 
	// Usage Examples:
	//   1. Focus on top 3 CPR clusters with 80% smash probability:
	//      CPRStrategyMode: "top", SmashProbability: 0.8
	//
	//   2. Use weighted strategy (higher CPR = higher smash probability):
	//      CPRStrategyMode: "weighted", SmashProbability: 1.0
	//
	//   3. Use adaptive strategy based on CPR threshold:
	//      CPRStrategyMode: "adaptive", AdaptiveThreshold: 0.8
	//
	// Runtime switching:
	//   fuzzer.UpdateCPRStrategy("top", 0.9, 0.7)     // Switch to top strategy
	//   fuzzer.UpdateCPRStrategy("weighted", 0.8, 0)  // Switch to weighted strategy
	//
	// Note: TopN is defined as constant TopCPRClusters = 3
	CPRStrategyMode            string              // Strategy mode: "top", "weighted", "adaptive" (default: "top")
	SmashProbability           float64             // Probability of using smash for top clusters (default: 1.0)
	AdaptiveThreshold          float64             // Threshold for adaptive strategy (default: 0.7)
}

func (fuzzer *Fuzzer) triageProgCall(p *prog.Prog, info *flatrpc.CallInfo, call int, triage *map[int]*triageCall) {
	if info == nil {
		return
	}
	prio := signalPrio(p, info, call)
	newMaxSignal := fuzzer.Cover.addRawMaxSignal(info.Signal, prio)
	if newMaxSignal.Empty() {
		return
	}
	if !fuzzer.Config.NewInputFilter(p.CallName(call)) {
		return
	}
	fuzzer.Logf(2, "found new signal in call %d in %s", call, p)
	if *triage == nil {
		*triage = make(map[int]*triageCall)
	}
	(*triage)[call] = &triageCall{
		errno:     info.Error,
		newSignal: newMaxSignal,
		signals:   [deflakeNeedRuns]signal.Signal{signal.FromRaw(info.Signal, prio)},
	}
}

func (fuzzer *Fuzzer) handleCallInfo(req *queue.Request, info *flatrpc.CallInfo, call int) {
	if info == nil || info.Flags&flatrpc.CallFlagCoverageOverflow == 0 {
		return
	}
	syscallIdx := len(fuzzer.Syscalls) - 1
	if call != -1 {
		syscallIdx = req.Prog.Calls[call].Meta.ID
	}
	stat := &fuzzer.Syscalls[syscallIdx]
	if req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectComps != 0 {
		stat.CompsOverflows.Add(1)
	} else {
		stat.CoverOverflows.Add(1)
	}
}

func signalPrio(p *prog.Prog, info *flatrpc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Error == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

// Initialize default long-term strategy configuration
func initializeLongTermConfig(cfg *Config) {
	if cfg.CPRStrategyMode == "" {
		cfg.CPRStrategyMode = "top"
	}
	if cfg.SmashProbability == 0 {
		cfg.SmashProbability = 1.0
	}
	if cfg.AdaptiveThreshold == 0 {
		cfg.AdaptiveThreshold = 0.7
	}
}

// Select mutation type based on configurable CPR strategy
func (fuzzer *Fuzzer) genFuzzLongterm() *queue.Request {
	mutationRate := 0.95

	var req *queue.Request
	rnd := fuzzer.rand()
	val := rnd.Float64()

	if val < mutationRate { // [0, 0.95) - mutation task
		// 1. First select original mutation seed through ChooseProgramCommunityUCB
		var selectedProg *prog.Prog
		if fuzzer.ClusterInfo != nil && fuzzer.Config.Corpus != nil {
			selectedProg = fuzzer.Config.Corpus.ChooseProgramCommunityUCB(rnd, fuzzer.ClusterInfo)
		} else {
			selectedProg = fuzzer.Config.Corpus.ChooseProgram(rnd)
		}

		if selectedProg != nil {
			// 2. Get cluster ID of selected seed
			progHash := GetProgHash(selectedProg)
			clusterID, exists := fuzzer.ClusterInfo.GetClusterID(progHash)
			
			mutationType := "mutate" // Default mutate mutation
			
			if exists && fuzzer.ClusterInfo != nil {
				// 3. Use configurable strategy to determine mutation type
				mutationType = fuzzer.selectMutationStrategy(clusterID, rnd)
			}

			// 4. Execute corresponding mutation based on mutation type
			
			originHash := GetProgHash(selectedProg)
			
			newP := selectedProg.Clone()
			newP.Mutate(rnd,
				prog.RecommendedCalls,
				fuzzer.ChoiceTable(),
				fuzzer.Config.NoMutateCalls,
				fuzzer.Config.Corpus.Programs(),
			)

			var stat *stat.Val
			if mutationType == "mutate" {
				stat = fuzzer.statExecFuzz
			} else {
				stat = fuzzer.statExecSmash
			}

			req = &queue.Request{
				Prog:           newP,
				ExecOpts:       setFlags(flatrpc.ExecFlagCollectSignal),
				Stat:           stat,
				OriginSeedHash: originHash,    
				MutationDepth:  1,             
				IsGenerated:    false,         
			}

			fuzzer.Logf(2, "genFuzzLongterm: Selected mutation type '%s' for seed from cluster %d (strategy: %s, topN: %d)", 
				mutationType, clusterID, fuzzer.Config.CPRStrategyMode, TopCPRClusters)
		}
	}

	// Fallback to generate if mutation failed or if in generation probability range
	if req == nil {
		req = genProgRequest(fuzzer, rnd)
	}

	// Final safeguard: genProgRequest should always return a valid program.
	if req == nil {
		fuzzer.Logf(0, "genFuzzLongterm: CRITICAL - All attempts to generate a program failed (req is still nil).")
		panic("genProgRequest returned nil, which is critical for fuzzer operation")
	}

	// Original collide logic
	if fuzzer.Config.Collide && rnd.Intn(3) == 0 {
		if req.Prog != nil {
			collidedProg := randomCollide(req.Prog, rnd)
			if collidedProg != nil {
				
				req = &queue.Request{
					Prog:           collidedProg,
					Stat:           fuzzer.statExecCollide,
					ExecOpts:       req.ExecOpts,
					OriginSeedHash: req.OriginSeedHash, 
					MutationDepth:  req.MutationDepth,  
					IsGenerated:    req.IsGenerated,   
				}
			}
		} else {
			fuzzer.Logf(0, "genFuzzLongterm: req.Prog is nil before collide, skipping collide. This is unexpected.")
		}
	}

	fuzzer.prepare(req, 0, 0)
	return req
}

// Restore original genFuzz function and add runtime check logic
func (fuzzer *Fuzzer) genFuzz() *queue.Request {
	// Check if runtime exceeds 10 hours
	if time.Since(fuzzer.startTime) > 4*time.Hour {
		// Runtime exceeds 10 hours, use long-term strategy
		return fuzzer.genFuzzLongterm()
	}

	// Runtime under 10 hours, use original short-term strategy
	mutateRate := 0.70
	smashPlusMutateRate := 0.70 + 0.25 // Combined probability for mutate and smash
	// genRate is implicitly 1.0 - smashPlusMutateRate = 0.05

	var req *queue.Request
	rnd := fuzzer.rand()
	val := rnd.Float64()

	taskSelected := ""

	if val < mutateRate { // [0, 0.70)
		taskSelected = "mutate"
		req = mutateProgRequest(fuzzer, rnd)
	} else if val < smashPlusMutateRate { // [0.70, 0.95)
		taskSelected = "smash"
		if fuzzer.ClusterInfo != nil && fuzzer.Config.Corpus != nil && len(fuzzer.Config.Corpus.Programs()) > 0 {
			progToSmash := fuzzer.ClusterInfo.ChooseProgramFromMaxCPRCluster(rnd, fuzzer.Config.Corpus.Programs(), GetProgHash)
			if progToSmash != nil {
				
				originHash := GetProgHash(progToSmash)
				
				smashedP := progToSmash.Clone()
				smashedP.Mutate(rnd,
					prog.RecommendedCalls,
					fuzzer.ChoiceTable(),
					fuzzer.Config.NoMutateCalls,
					fuzzer.Config.Corpus.Programs(),
				)
				req = &queue.Request{
					Prog:           smashedP,
					ExecOpts:       setFlags(flatrpc.ExecFlagCollectSignal),
					Stat:           fuzzer.statExecSmash,
					OriginSeedHash: originHash,    
					MutationDepth:  1,             
					IsGenerated:    false,         
				}
			} else {
				fuzzer.Logf(2, "genFuzz: ChooseProgramFromMaxCPRCluster returned nil, falling back to generate.")
			}
		} else {
			fuzzer.Logf(2, "genFuzz: ClusterInfo not available or corpus empty for smash, falling back to generate.")
		}
	} else { // [0.95, 1.0)
		taskSelected = "generate"
		// This path is for explicit generation by probability.
		// req will be nil here, triggering the fallback to genProgRequest below.
	}

	// Fallback to generate if the chosen task did not produce a request or if it was generate task by probability
	if req == nil {
		if taskSelected == "" { // Should not happen if logic above is correct
			fuzzer.Logf(0, "genFuzz: taskSelected is empty, falling back to generate. This indicates a logic error.")
		} else if taskSelected != "generate" { // Log if mutate or smash failed
			fuzzer.Logf(2, "genFuzz: Task '%s' did not produce a request, falling back to generate.", taskSelected)
		}
		req = genProgRequest(fuzzer, rnd)
	}

	// Final safeguard: genProgRequest should always return a valid program.
	if req == nil {
		// This case should ideally not be reached if genProgRequest is robust.
		// Handle this as a critical error, as the fuzzer cannot proceed without a program.
		fuzzer.Logf(0, "genFuzz: CRITICAL - All attempts to generate a program failed (req is still nil).")
		// Depending on desired robustness, could panic or attempt a very simple generation.
		// For now, let's assume genProgRequest won't return nil. If it can, that needs specific handling.
		panic("genProgRequest returned nil, which is critical for fuzzer operation")
	}

	// Original collide logic
	if fuzzer.Config.Collide && rnd.Intn(3) == 0 {
		if req.Prog != nil {
			collidedProg := randomCollide(req.Prog, rnd)
			if collidedProg != nil {
				
				req = &queue.Request{
					Prog:           collidedProg,
					Stat:           fuzzer.statExecCollide,
					ExecOpts:       req.ExecOpts,
					OriginSeedHash: req.OriginSeedHash, 
					MutationDepth:  req.MutationDepth,  
					IsGenerated:    req.IsGenerated,    
				}
			}
		} else {
			// This can happen if the program from genProgRequest was nil, which is guarded above.
			fuzzer.Logf(0, "genFuzz: req.Prog is nil before collide, skipping collide. This is unexpected.")
		}
	}

	fuzzer.prepare(req, 0, 0)
	return req
}

// New helper function: get cluster density ranking
func (fuzzer *Fuzzer) getClusterDensityRanking() []ClusterDensityPair {
	if fuzzer.ClusterInfo == nil {
		return nil
	}

	fuzzer.ClusterInfo.RLock()
	defer fuzzer.ClusterInfo.RUnlock()

	var clusterDensities []ClusterDensityPair
	for clusterID, size := range fuzzer.ClusterInfo.ClusterSizes {
		clusterDensities = append(clusterDensities, ClusterDensityPair{
			ID:   clusterID,
			Size: size,
		})
	}

	// Sort by cluster size in descending order (highest density first)
	sort.Slice(clusterDensities, func(i, j int) bool {
		return clusterDensities[i].Size > clusterDensities[j].Size
	})

	return clusterDensities
}

// New helper function: get cluster CPR ranking
func (fuzzer *Fuzzer) getClusterCPRRanking() []ClusterCPRPair {
	if fuzzer.ClusterInfo == nil {
		return nil
	}

	fuzzer.ClusterInfo.RLock()
	defer fuzzer.ClusterInfo.RUnlock()

	var clusterCPRs []ClusterCPRPair
	for clusterID, size := range fuzzer.ClusterInfo.ClusterSizes {
		if size == 0 {
			continue // Skip empty clusters
		}
		
		// Calculate CPR for this cluster
		density := float64(size) / float64(fuzzer.ClusterInfo.TotalClusterSize)
		if density == 0 {
			continue // Skip clusters with zero density
		}
		
		accessCount := float64(fuzzer.ClusterInfo.AccessCount[clusterID])
		cpr := (accessCount + 1.0) / density 
		
		clusterCPRs = append(clusterCPRs, ClusterCPRPair{
			ID:  clusterID,
			CPR: cpr,
		})
	}

	// Sort by CPR in descending order (highest CPR first)
	sort.Slice(clusterCPRs, func(i, j int) bool {
		return clusterCPRs[i].CPR > clusterCPRs[j].CPR
	})

	return clusterCPRs
}

// selectMutationStrategy determines mutation type based on configurable CPR strategy
// 
// Three strategy modes are supported:
//   1. "top": Binary classification - smash for top N clusters, mutate for others
//   2. "weighted": Probability-based - higher CPR rank = higher smash probability  
//   3. "adaptive": Threshold-based - adjust probability based on actual CPR value
//
func (fuzzer *Fuzzer) selectMutationStrategy(clusterID int, rnd *rand.Rand) string {
	switch fuzzer.Config.CPRStrategyMode {
	case "top":
		return fuzzer.topCPRStrategy(clusterID, rnd)
	case "weighted":
		return fuzzer.weightedCPRStrategy(clusterID, rnd)
	case "adaptive":
		return fuzzer.adaptiveCPRStrategy(clusterID, rnd)
	default:
		// Default to top strategy
		return fuzzer.topCPRStrategy(clusterID, rnd)
	}
}

// topCPRStrategy: Use smash for top N CPR clusters, mutate for others
//
// Logic:
//   - If cluster is in top N CPR clusters: use smash with configured probability
//   - Otherwise: always use mutate
//
// Example with TopCPRClusters=3, SmashProbability=0.8:
//   - Top 3 clusters: 80% chance smash, 20% chance mutate
//   - Other clusters: 100% chance mutate
//
func (fuzzer *Fuzzer) topCPRStrategy(clusterID int, rnd *rand.Rand) string {
	clusterCPRs := fuzzer.getClusterCPRRanking()
	
	// Check if clusterID is in top N CPR clusters
	topN := TopCPRClusters
	if topN > len(clusterCPRs) {
		topN = len(clusterCPRs)
	}
	
	for i := 0; i < topN; i++ {
		if clusterCPRs[i].ID == clusterID {
			// Apply smash probability
			if rnd.Float64() < fuzzer.Config.SmashProbability {
				return "smash"
			}
			return "mutate"
		}
	}
	
	return "mutate"
}

// weightedCPRStrategy: Probability of smash based on CPR ranking
//
// Logic:
//   - Smash probability = (totalClusters - rank) / totalClusters * SmashProbability
//   - Higher rank (lower index) = higher probability
//
// Example with 5 clusters, SmashProbability=0.9:
//   - Rank 0 (highest CPR): 90% chance smash
//   - Rank 1: 72% chance smash
//   - Rank 2: 54% chance smash
//   - Rank 3: 36% chance smash
//   - Rank 4: 18% chance smash
//
func (fuzzer *Fuzzer) weightedCPRStrategy(clusterID int, rnd *rand.Rand) string {
	clusterCPRs := fuzzer.getClusterCPRRanking()
	
	// Find cluster rank
	rank := -1
	for i, cluster := range clusterCPRs {
		if cluster.ID == clusterID {
			rank = i
			break
		}
	}
	
	if rank == -1 {
		return "mutate"
	}
	
	// Calculate probability based on rank (higher rank = higher probability)
	// P = (totalClusters - rank) / totalClusters * smashProbability
	totalClusters := len(clusterCPRs)
	if totalClusters == 0 {
		return "mutate"
	}
	
	probability := float64(totalClusters-rank) / float64(totalClusters) * fuzzer.Config.SmashProbability
	
	if rnd.Float64() < probability {
		return "smash"
	}
	
	return "mutate"
}

// adaptiveCPRStrategy: Adjust strategy based on recent performance
//
// Logic:
//   - Only consider top N CPR clusters
//   - If cluster CPR > AdaptiveThreshold: use full SmashProbability
//   - If cluster CPR <= AdaptiveThreshold: use reduced SmashProbability (50%)
//   - Other clusters: always use mutate
//
// Example with TopCPRClusters=3, AdaptiveThreshold=0.7, SmashProbability=0.8:
//   - Top 3 clusters with CPR > 0.7: 80% chance smash
//   - Top 3 clusters with CPR <= 0.7: 40% chance smash
//   - Other clusters: 100% chance mutate
//
func (fuzzer *Fuzzer) adaptiveCPRStrategy(clusterID int, rnd *rand.Rand) string {
	clusterCPRs := fuzzer.getClusterCPRRanking()
	
	// Check if clusterID is in top N CPR clusters
	topN := TopCPRClusters
	if topN > len(clusterCPRs) {
		topN = len(clusterCPRs)
	}
	
	isInTopN := false
	clusterCPR := 0.0
	for i := 0; i < topN && i < len(clusterCPRs); i++ {
		if clusterCPRs[i].ID == clusterID {
			isInTopN = true
			clusterCPR = clusterCPRs[i].CPR
			break
		}
	}
	
	if !isInTopN {
		return "mutate"
	}
	
	// Adaptive logic based on CPR value
	// If CPR is above threshold, use smash with higher probability
	if clusterCPR > fuzzer.Config.AdaptiveThreshold {
		smashProb := fuzzer.Config.SmashProbability
		if rnd.Float64() < smashProb {
			return "smash"
		}
	} else {
		// If CPR is below threshold, use smash with reduced probability
		reducedProb := fuzzer.Config.SmashProbability * 0.5
		if rnd.Float64() < reducedProb {
			return "smash"
		}
	}
	
	return "mutate"
}

// UpdateCPRStrategy allows dynamic update of CPR strategy configuration
//
// Parameters:
//   mode: "top", "weighted", or "adaptive" (empty string = no change)
//   smashProb: probability of using smash [0.0-1.0] (negative = no change)
//   adaptiveThreshold: threshold for adaptive strategy [0.0-1.0] (negative = no change)
//
// Usage examples:
//   fuzzer.UpdateCPRStrategy("top", 0.9, -1)      // Switch to top strategy
//   fuzzer.UpdateCPRStrategy("weighted", 0.8, -1) // Switch to weighted strategy
//   fuzzer.UpdateCPRStrategy("", -1, 0.8)         // Change adaptive threshold only
//
// Note: TopN is defined as constant TopCPRClusters = 3
func (fuzzer *Fuzzer) UpdateCPRStrategy(mode string, smashProb float64, adaptiveThreshold float64) {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	
	if mode != "" {
		fuzzer.Config.CPRStrategyMode = mode
	}
	if smashProb >= 0 && smashProb <= 1.0 {
		fuzzer.Config.SmashProbability = smashProb
	}
	if adaptiveThreshold >= 0 && adaptiveThreshold <= 1.0 {
		fuzzer.Config.AdaptiveThreshold = adaptiveThreshold
	}
	
	fuzzer.Logf(0, "Updated CPR strategy - Mode: %s, TopN: %d, SmashProb: %.2f, AdaptiveThreshold: %.2f", 
		fuzzer.Config.CPRStrategyMode, TopCPRClusters, 
		fuzzer.Config.SmashProbability, fuzzer.Config.AdaptiveThreshold)
}

// GetCPRStrategyInfo returns current CPR strategy configuration
//
// Returns a map containing:
//   - "mode": current strategy mode
//   - "top_cpr_clusters": number of top clusters to focus on (constant TopCPRClusters = 3)
//   - "smash_probability": probability of using smash
//   - "adaptive_threshold": threshold for adaptive strategy
//   - "current_cpr_ranking": live CPR ranking of all clusters (if available)
//
// Usage example:
//   info := fuzzer.GetCPRStrategyInfo()
//   fmt.Printf("Current strategy: %s, Top N: %d\n", info["mode"], info["top_cpr_clusters"])
//
func (fuzzer *Fuzzer) GetCPRStrategyInfo() map[string]interface{} {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	
	info := map[string]interface{}{
		"mode":              fuzzer.Config.CPRStrategyMode,
		"top_cpr_clusters":  TopCPRClusters,
		"smash_probability": fuzzer.Config.SmashProbability,
		"adaptive_threshold": fuzzer.Config.AdaptiveThreshold,
	}
	
	// Add current cluster CPR ranking if available
	if fuzzer.ClusterInfo != nil {
		clusterCPRs := fuzzer.getClusterCPRRanking()
		if len(clusterCPRs) > 0 {
			info["current_cpr_ranking"] = clusterCPRs
		}
	}
	
	return info
}

func (fuzzer *Fuzzer) startJob(stat *stat.Val, newJob job) {
	fuzzer.Logf(2, "started %T", newJob)
	go func() {
		stat.Add(1)
		defer stat.Add(-1)

		fuzzer.statJobs.Add(1)
		defer fuzzer.statJobs.Add(-1)

		if obj, ok := newJob.(jobIntrospector); ok {
			fuzzer.mu.Lock()
			fuzzer.runningJobs[obj] = struct{}{}
			fuzzer.mu.Unlock()

			defer func() {
				fuzzer.mu.Lock()
				delete(fuzzer.runningJobs, obj)
				fuzzer.mu.Unlock()
			}()
		}

		newJob.run(fuzzer)
	}()
}

func (fuzzer *Fuzzer) Next() *queue.Request {
	req := fuzzer.source.Next()
	if req == nil {
		// The fuzzer is not supposed to issue nil requests.
		panic("nil request from the fuzzer")
	}
	return req
}

func (fuzzer *Fuzzer) Logf(level int, msg string, args ...interface{}) {
	if fuzzer.Config.Logf == nil {
		return
	}
	fuzzer.Config.Logf(level, msg, args...)
}

type ProgFlags int

const (
	// The candidate was loaded from our local corpus rather than come from hub.
	ProgFromCorpus ProgFlags = 1 << iota
	ProgMinimized
	ProgSmashed

	progCandidate
	progInTriage
	
	// CPR strategy constants
	TopCPRClusters = 3  // Number of top CPR clusters to focus on
)

type Candidate struct {
	Prog  *prog.Prog
	Flags ProgFlags
}

// AddCandidates adds candidate seeds to queue using dynamic seed classification
func (fuzzer *Fuzzer) AddCandidates(candidates []Candidate) {
	fuzzer.statCandidates.Add(len(candidates))

	// If cluster info exists, handle seed classification
	hasClusterInfo := fuzzer.ClusterInfo != nil

	for _, candidate := range candidates {
		// Get program hash
		progHash := GetProgHash(candidate.Prog)

		// If cluster info is enabled, check existing cluster assignment or assign new cluster
		if hasClusterInfo {
			// First check if seed already has cluster assignment
			existingClusterID, exists := fuzzer.ClusterInfo.GetClusterID(progHash)

			if exists {
				// Seed already has cluster assignment, log and use existing assignment
				fuzzer.Logf(3, "Using existing cluster %d for seed %s", existingClusterID, progHash)

				// If seed is cluster center, store its program object
				fuzzer.ClusterInfo.StoreProgramInCluster(candidate.Prog, progHash, existingClusterID)
			} else {
				// Seed has no cluster assignment, perform dynamic classification
				clusterID, isNewCluster := fuzzer.ClusterInfo.AssignCluster(candidate.Prog, progHash)

				// If new cluster is created, log it
				if isNewCluster {
					fuzzer.Logf(0, "Created new cluster %d for seed %s", clusterID, progHash)
				} else {
					//fuzzer.Logf(2, "Assigned seed %s to cluster %d", progHash, clusterID)
				}

				// If seed is cluster center, store its program object
				fuzzer.ClusterInfo.StoreProgramInCluster(candidate.Prog, progHash, clusterID)
			}
		}

		req := &queue.Request{
			Prog:         candidate.Prog,
			ExecOpts:     setFlags(flatrpc.ExecFlagCollectSignal),
			Stat:         fuzzer.statExecCandidate,
			Important:    true,
			IsGenerated:  false,  // 候选种子通常来自corpus
			MutationDepth: 0,     // 候选种子不是突变产生
		}
		fuzzer.enqueue(fuzzer.candidateQueue, req, candidate.Flags|progCandidate, 0)
	}
}

// updateCandidateQueuePriority periodically updates candidate queue priority using UCB strategy
func (fuzzer *Fuzzer) updateCandidateQueuePriority() {
	// Check if fuzzer is nil at the beginning of the method
	if fuzzer == nil {
		return
	}

	// Set delayed start flag (use atomic operations instead of atomic.Bool)
	var priorityUpdateReady int32 = 0

	// Add delayed initialization, set to ready after 2 minutes
	time.AfterFunc(2*time.Minute, func() {
		atomic.StoreInt32(&priorityUpdateReady, 1)
		fuzzer.Logf(0, "Priority updater is now ready")
	})

	// Only lock the check part at the beginning of the method
	fuzzer.mu.Lock()
	if fuzzer.ClusterInfo == nil || fuzzer.candidateQueue == nil {
		if fuzzer.candidateQueue == nil {
			fuzzer.Logf(0, "warning: candidateQueue is nil, cannot update priorities")
		}
		if fuzzer.ClusterInfo == nil {
			fuzzer.Logf(0, "warning: ClusterInfo is nil, cannot update priorities")
		}
		fuzzer.mu.Unlock() // Important: unlock before return
		return
	}
	fuzzer.mu.Unlock() // Unlock for subsequent operations

	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-fuzzer.ctx.Done():
			return
		case <-ticker.C:
			// Check if ready for priority update
			if atomic.LoadInt32(&priorityUpdateReady) != 1 {
				fuzzer.Logf(2, "Priority updater not ready yet, waiting")
				continue
			}

			// Use anonymous function to wrap update logic and add exception handling
			func() {
				defer func() {
					if r := recover(); r != nil {
						// Catch all possible panics
						fuzzer.Logf(0, "PANIC in updateCandidateQueuePriority: %v", r)
						// Print stack trace to help debugging
						buf := make([]byte, 4096)
						n := runtime.Stack(buf, false)
						fuzzer.Logf(0, "Stack trace: %s", buf[:n])
					}
				}()

				// Check necessary fields again as they might have been modified during waiting
				fuzzer.mu.Lock()
				if fuzzer.ClusterInfo == nil || fuzzer.candidateQueue == nil || fuzzer.Cover == nil {
					fuzzer.mu.Unlock()
					return
				}
				fuzzer.mu.Unlock()

				// Record start time for performance tracking
				startTime := time.Now()
				// fuzzer.Logf(0, "Updating candidate queue priority using UCB strategy")

				// Get all requests in the queue
				var requests []*queue.Request
				fuzzer.mu.Lock()
				if fuzzer.candidateQueue != nil {
					requests = fuzzer.candidateQueue.GetAllRequests()
				}
				fuzzer.mu.Unlock()

				if len(requests) == 0 {
					fuzzer.Logf(1, "No requests in queue, skipping update")
					return
				}

				// Calculate UCB scores
				type progScore struct {
					req   *queue.Request
					score float64
				}

				scores := make([]progScore, 0, len(requests))

				fuzzer.mu.Lock()
				totalRounds := fuzzer.ClusterInfo.TotalAccess + 1 // Avoid division by zero
				fuzzer.mu.Unlock()

				exploreCoef := math.Sqrt(2.0)

				// Maximum values for normalization
				var maxSignal float64 = 1.0
				var maxSizeInv float64 = 1.0

				// First pass: collect normalization info and filter invalid requests
				validRequests := make([]*queue.Request, 0, len(requests))
				for _, req := range requests {
					if req == nil || req.Prog == nil {
						continue // Skip invalid requests
					}

					validRequests = append(validRequests, req)

					// Safely get program hash
					progHash := GetProgHash(req.Prog)
					if progHash == "" {
						continue // Skip invalid hash
					}

					fuzzer.mu.Lock()
					if fuzzer.Cover == nil {
						fuzzer.mu.Unlock()
						continue // Ensure Cover is not nil
					}
					signalSize := float64(fuzzer.Cover.GetSignalSize(progHash))
					fuzzer.mu.Unlock()

					if signalSize > maxSignal {
						maxSignal = signalSize
					}

					if len(req.Prog.Calls) > 0 {
						sizeInv := 1.0 / float64(len(req.Prog.Calls))
						if sizeInv > maxSizeInv {
							maxSizeInv = sizeInv
						}
					}
				}

				// If no valid requests, skip update
				if len(validRequests) == 0 {
					fuzzer.Logf(1, "No valid requests found, skipping update")
					return
				}

				fuzzer.Logf(1, "Processing %d valid requests for priority update", len(validRequests))

				// Second pass: calculate UCB scores
				for _, req := range validRequests {
					// Ensure request is valid
					if req == nil || req.Prog == nil {
						continue
					}

					hash := GetProgHash(req.Prog)
					if hash == "" {
						continue // Skip invalid hash
					}

					fuzzer.mu.Lock()
					if fuzzer.ClusterInfo == nil {
						fuzzer.mu.Unlock()
						return // ClusterInfo became nil, exit directly
					}

					clusterID, exists := fuzzer.ClusterInfo.GetClusterID(hash)
					if !exists {
						clusterID = fuzzer.ClusterInfo.AssignDefaultCluster(hash)
					}
					fuzzer.mu.Unlock()

					// Default score components
					var densityScore float64 = 0.5 // Default medium density
					var signalScore float64 = 0.0
					var sizeScore float64 = 0.0
					var exploreScore float64 = 1.0 // Default high exploration reward

					// Signal coverage score - normalized
					fuzzer.mu.Lock()
					if fuzzer.Cover != nil {
						signalSize := float64(fuzzer.Cover.GetSignalSize(hash))
						if maxSignal > 0 {
							signalScore = signalSize / maxSignal
						}
					}
					fuzzer.mu.Unlock()

					// Size score - normalized (smaller is better)
					if len(req.Prog.Calls) > 0 {
						sizeInv := 1.0 / float64(len(req.Prog.Calls))
						if maxSizeInv > 0 {
							sizeScore = sizeInv / maxSizeInv
						}
					}

					// Cluster density score - lower is better
					fuzzer.mu.Lock()
					if fuzzer.ClusterInfo == nil {
						fuzzer.mu.Unlock()
						return
					}
					density := float64(fuzzer.ClusterInfo.GetClusterSize(clusterID))
					fuzzer.mu.Unlock()

					if density > 0 {
						densityScore = 1.0 / density
					}

					// Access frequency used to calculate exploration score
					fuzzer.mu.Lock()
					if fuzzer.ClusterInfo == nil {
						fuzzer.mu.Unlock()
						return
					}
					visits := float64(fuzzer.ClusterInfo.GetAccessCount(clusterID)) + 1.0

					// Update cluster access statistics
					fuzzer.ClusterInfo.UpdateClusterAccess(clusterID)
					fuzzer.mu.Unlock()

					// UCB exploration term - avoid division by zero
					if visits > 0 {
						exploreScore = exploreCoef * math.Sqrt(math.Log(float64(totalRounds))/visits)
					}

					// Weight coefficients
					w1 := 0.4 // Density weight
					w2 := 0.3 // Signal coverage weight
					w3 := 0.2 // Program size weight
					w4 := 0.1 // Exploration weight

					// Final UCB score
					finalScore := w1*densityScore + w2*signalScore + w3*sizeScore + w4*exploreScore

					scores = append(scores, progScore{
						req:   req,
						score: finalScore,
					})
				}

				// If no valid scores calculated, skip update
				if len(scores) == 0 {
					fuzzer.Logf(1, "No valid scores calculated, skipping update")
					return
				}

				// Sort scores
				sort.Slice(scores, func(i, j int) bool {
					return scores[i].score > scores[j].score
				})

				// Rebuild queue
				newItems := make([]*queue.Request, 0, len(scores))
				for _, ps := range scores {
					newItems = append(newItems, ps.req)
				}

				// Final check before operation
				fuzzer.mu.Lock()
				if fuzzer.candidateQueue != nil {
					fuzzer.candidateQueue.ReplaceRequests(newItems)
					duration := time.Since(startTime)
					fuzzer.Logf(0, "Candidate queue updated: %d items in %v", len(newItems), duration)
				}
				fuzzer.mu.Unlock()
			}()
		}
	}
}

func (fuzzer *Fuzzer) rand() *rand.Rand {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()
	return rand.New(rand.NewSource(fuzzer.rnd.Int63()))
}

func (fuzzer *Fuzzer) updateChoiceTable(programs []*prog.Prog) {
	newCt := fuzzer.target.BuildChoiceTable(programs, fuzzer.Config.EnabledCalls)

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()
	if len(programs) >= fuzzer.ctProgs {
		fuzzer.ctProgs = len(programs)
		fuzzer.ct = newCt
	}
}

func (fuzzer *Fuzzer) choiceTableUpdater() {
	for {
		select {
		case <-fuzzer.ctx.Done():
			return
		case <-fuzzer.ctRegenerate:
		}
		fuzzer.updateChoiceTable(fuzzer.Config.Corpus.Programs())
	}
}

func (fuzzer *Fuzzer) ChoiceTable() *prog.ChoiceTable {
	progs := fuzzer.Config.Corpus.Programs()

	fuzzer.ctMu.Lock()
	defer fuzzer.ctMu.Unlock()

	// There were no deep ideas nor any calculations behind these numbers.
	regenerateEveryProgs := 333
	if len(progs) < 100 {
		regenerateEveryProgs = 33
	}
	if fuzzer.ctProgs+regenerateEveryProgs < len(progs) {
		select {
		case fuzzer.ctRegenerate <- struct{}{}:
		default:
			// We're okay to lose the message.
			// It means that we're already regenerating the table.
		}
	}
	return fuzzer.ct
}

func (fuzzer *Fuzzer) RunningJobs() []*JobInfo {
	fuzzer.mu.Lock()
	defer fuzzer.mu.Unlock()

	var ret []*JobInfo
	for item := range fuzzer.runningJobs {
		ret = append(ret, item.getInfo())
	}
	return ret
}

func (fuzzer *Fuzzer) logCurrentStats() {
	for {
		select {
		case <-time.After(time.Minute):
		case <-fuzzer.ctx.Done():
			return
		}

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		str := fmt.Sprintf("running jobs: %d, heap (MB): %d",
			fuzzer.statJobs.Val(), m.Alloc/1000/1000)
		fuzzer.Logf(0, "%s", str)
	}
}

func setFlags(execFlags flatrpc.ExecFlag) flatrpc.ExecOpts {
	return flatrpc.ExecOpts{
		ExecFlags: execFlags,
	}
}

// TODO: This method belongs better to pkg/flatrpc, but we currently end up
// having a cyclic dependency error.
func DefaultExecOpts(cfg *mgrconfig.Config, features flatrpc.Feature, debug bool) flatrpc.ExecOpts {
	env := csource.FeaturesToFlags(features, nil)
	if debug {
		env |= flatrpc.ExecEnvDebug
	}
	if cfg.Experimental.ResetAccState {
		env |= flatrpc.ExecEnvResetState
	}
	if cfg.Cover {
		env |= flatrpc.ExecEnvSignal
	}
	sandbox, err := flatrpc.SandboxToFlags(cfg.Sandbox)
	if err != nil {
		panic(fmt.Sprintf("failed to parse sandbox: %v", err))
	}
	env |= sandbox

	exec := flatrpc.ExecFlagThreaded
	if !cfg.RawCover {
		exec |= flatrpc.ExecFlagDedupCover
	}
	return flatrpc.ExecOpts{
		EnvFlags:   env,
		ExecFlags:  exec,
		SandboxArg: cfg.SandboxArg,
	}
}

// Initialize ClusterInfo settings when initializing
func (fuzzer *Fuzzer) initClusterInfo(cfg *Config) {
	if cfg.ClusterInfo == nil {
		fuzzer.Logf(0, "No cluster info provided, skipping dynamic clustering")
		return
	}

	// Set target for program parsing
	cfg.ClusterInfo.SetTarget(fuzzer.target)

	// Set threshold, can be read from config
	threshold := 0.4 // Default threshold
	if cfg.ClusterSimilarityThreshold > 0 {
		threshold = cfg.ClusterSimilarityThreshold
	}
	cfg.ClusterInfo.SetSimilarityThreshold(threshold)

	// Load cluster center information
	clusterCorePath := filepath.Join(cfg.Workdir, "cluster_core.csv")
	if err := cfg.ClusterInfo.LoadClusterCores(clusterCorePath); err != nil {
		fuzzer.Logf(0, "failed to load cluster cores: %v", err)
	} else {
		fuzzer.Logf(0, "loaded cluster core information with %d centers",
			len(cfg.ClusterInfo.ClusterCenters))
	}
}

// Periodically save cluster center information
func (fuzzer *Fuzzer) periodicSaveClusterInfo() {
	if fuzzer.ClusterInfo == nil {
		return
	}

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		// Perform final save before exit
		case <-fuzzer.ctx.Done():
			// In actual applications, a more graceful shutdown and save mechanism might be needed
			fuzzer.Logf(0, "Context done, attempting final save of cluster info.")
			clusterPath := filepath.Join(fuzzer.Config.Workdir, "cluster_info_final.csv")
			if err := fuzzer.ClusterInfo.SaveClusterLabel(clusterPath); err != nil {
				fuzzer.Logf(0, "failed to save final cluster info: %v", err)
			} else {
				fuzzer.Logf(0, "saved final cluster information to %s", clusterPath)
			}

			clusterCorePath := filepath.Join(fuzzer.Config.Workdir, "cluster_core_final.csv")
			if err := fuzzer.ClusterInfo.SaveClusterCores(clusterCorePath); err != nil {
				fuzzer.Logf(0, "failed to save final cluster cores: %v", err)
			} else {
				fuzzer.Logf(0, "saved final cluster core information to %s", clusterCorePath)
			}

			astDir := filepath.Join(fuzzer.Config.Workdir, "ast_cache_final")
			if err := fuzzer.ClusterInfo.SaveClusterASTs(astDir); err != nil {
				fuzzer.Logf(0, "failed to save final cluster ASTs: %v", err)
			} else {
				fuzzer.Logf(0, "saved final cluster AST information to %s", astDir)
			}
			return // Exit goroutine
		case <-ticker.C:
			// Save updated clustering information
			clusterPath := filepath.Join(fuzzer.Config.Workdir, "cluster_info.csv")
			if err := fuzzer.ClusterInfo.SaveClusterLabel(clusterPath); err != nil {
				fuzzer.Logf(0, "failed to save cluster info: %v", err)
			} else {
				fuzzer.Logf(2, "saved updated cluster information")
			}

			// Save cluster center information
			clusterCorePath := filepath.Join(fuzzer.Config.Workdir, "cluster_core.csv")
			if err := fuzzer.ClusterInfo.SaveClusterCores(clusterCorePath); err != nil {
				fuzzer.Logf(0, "failed to save cluster cores: %v", err)
			} else {
				fuzzer.Logf(2, "saved updated cluster core information")
			}

			// Can save AST information
			astDir := filepath.Join(fuzzer.Config.Workdir, "ast_cache")
			if err := fuzzer.ClusterInfo.SaveClusterASTs(astDir); err != nil {
				fuzzer.Logf(0, "failed to save cluster ASTs: %v", err)
			} else {
				fuzzer.Logf(3, "saved updated cluster AST information")
			}
		}
	}
}

// ucbUpdateWorker handles UCB data update tasks
func (fuzzer *Fuzzer) ucbUpdateWorker() {
	defer close(fuzzer.ucbWorkerDone)
	
	updateCount := 0
	for {
		select {
		case <-fuzzer.ctx.Done():
			return
		case task := <-fuzzer.ucbUpdateChan:
			updateCount++
			fuzzer.processUCBUpdate(task)
			
			// Check memory cleanup every 100 processed tasks
			if updateCount%100 == 0 && fuzzer.ClusterInfo != nil {
				fuzzer.ClusterInfo.TryCleanupMemory()
			}
		}
	}
}

// processUCBUpdate processes single UCB update task (original goroutine content)
func (fuzzer *Fuzzer) processUCBUpdate(data ucbUpdateTask) {
	if fuzzer.ClusterInfo == nil {
		return
	}

	ci := fuzzer.ClusterInfo
	ci.Lock()
	defer ci.Unlock()

	var currentExecutionSignal signal.Signal
	var deltaCovLen int

	if len(data.rawCover) > 0 {
		// Set simple priority
		var aggregateSignalPrio uint8 = 1 // Default priority
		if data.bugCount > 0 {
			aggregateSignalPrio = 2 // If bugs are found, higher priority
		}
		currentExecutionSignal = signal.FromRaw(data.rawCover, aggregateSignalPrio)

		ci.SeedCoverageSize[data.hash] = currentExecutionSignal.Len()

		if ci.TotalCoverage == nil {
			ci.TotalCoverage = make(signal.Signal)
		}

		gainSignal := ci.TotalCoverage.Diff(currentExecutionSignal)
		deltaCovLen = gainSignal.Len()

		ci.TotalCoverage.Merge(currentExecutionSignal)

		if ci.CoverLastUpdate == nil {
			ci.CoverLastUpdate = make(map[string]time.Time)
		}
		ci.CoverLastUpdate[data.hash] = time.Now()
		if fuzzer.Config.Debug {
			fuzzer.Logf(2, "UCB Worker: Prog %s, new signal len: %d, deltaCov: %d, totalCov: %d, aggPrio: %d",
				data.hash[:8], currentExecutionSignal.Len(), deltaCovLen, ci.TotalCoverage.Len(), aggregateSignalPrio)
		}
	} else {
		deltaCovLen = 0
		if fuzzer.Config.Debug {
			fuzzer.Logf(2, "UCB Worker: Prog %s, no new raw cover", data.hash[:8])
		}
	}

	// Update execution time
	if ci.SeedExecutionTime == nil {
		ci.SeedExecutionTime = make(map[string]time.Duration)
	}
	ci.SeedExecutionTime[data.hash] = data.execTime

	// Update bug count
	if data.bugCount > 0 {
		if ci.SeedBugCount == nil {
			ci.SeedBugCount = make(map[string]int)
		}
		ci.SeedBugCount[data.hash] += data.bugCount
		if fuzzer.Config.Debug {
			fuzzer.Logf(2, "UCB Worker: Prog %s, bugCount incremented by %d, total %d",
				data.hash[:8], data.bugCount, ci.SeedBugCount[data.hash])
		}
	}

	// If program is from corpus, calculate reward
	if data.isFromCorpus {
		var instantSeedReward float64
		execTimeSec := data.execTime.Seconds()
		if execTimeSec < 0.001 {
			execTimeSec = 0.001
		}

		currentSeedBugCount := ci.SeedBugCount[data.hash]
		instantSeedReward = (float64(deltaCovLen) / execTimeSec) * math.Log1p(float64(currentSeedBugCount))

		if deltaCovLen == 0 && currentSeedBugCount > 0 && instantSeedReward == 0 {
			instantSeedReward = 0.01 * math.Log1p(float64(currentSeedBugCount))
		}

		if _, ok := ci.SeedSumRewards[data.hash]; !ok {
			ci.SeedSumRewards[data.hash] = 0.0
			ci.SeedRewardCounts[data.hash] = 0
		}
		ci.SeedSumRewards[data.hash] += instantSeedReward
		ci.SeedRewardCounts[data.hash]++

		if fuzzer.Config.Debug {
			fuzzer.Logf(2, "UCB Worker: Prog %s (Corpus), Δcov: %d, bugs: %d, exec: %.3fs, seed_reward: %.4f, sum_reward: %.4f, count: %d",
				data.hash[:8], deltaCovLen, currentSeedBugCount, execTimeSec, instantSeedReward, ci.SeedSumRewards[data.hash], ci.SeedRewardCounts[data.hash])
		}

		// Update cluster reward
		clusterID, clusterExists := ci.SeedClusterMap[data.hash]
		if !clusterExists {
			clusterID, clusterExists = ci.ProgramHashes[data.hash]
		}

		if clusterExists {
			var instantClusterReward float64
			currentClusterSize := ci.ClusterSizes[clusterID]
			if currentClusterSize > 0 {
				var sumCovSijInCluster float64
				var seedsInClusterCount int

				for sHash, cID := range ci.SeedClusterMap {
					if cID == clusterID {
						seedsInClusterCount++
						sumCovSijInCluster += float64(ci.SeedCoverageSize[sHash])
					}
				}

				avgCovInCluster := 0.0
				if seedsInClusterCount > 0 {
					avgCovInCluster = sumCovSijInCluster / float64(seedsInClusterCount)
				}

				density := 0.0
				if ci.TotalClusterSize > 0 {
					density = float64(currentClusterSize) / float64(ci.TotalClusterSize)
				}
				if density == 0 {
					density = 0.001
				}
				nCi_t := float64(ci.AccessCount[clusterID]) + 1.0
				communityPopularityRate := nCi_t / density
				instantClusterReward = avgCovInCluster + ci.ExplorationRate*communityPopularityRate
			} else {
				instantClusterReward = 0.0
			}

			if _, ok := ci.ClusterSumRewards[clusterID]; !ok {
				ci.ClusterSumRewards[clusterID] = 0.0
				ci.ClusterRewardCounts[clusterID] = 0
			}
			ci.ClusterSumRewards[clusterID] += instantClusterReward
			ci.ClusterRewardCounts[clusterID]++
			if fuzzer.Config.Debug {
				fuzzer.Logf(2, "UCB Worker: Prog %s, Cluster %d, cluster_reward: %.4f, sum_reward: %.4f, count: %d",
					data.hash[:8], clusterID, instantClusterReward, ci.ClusterSumRewards[clusterID], ci.ClusterRewardCounts[clusterID])
			}
		} else {
			if fuzzer.Config.Debug {
				fuzzer.Logf(2, "UCB Worker: Prog %s from corpus has no cluster assigned for reward calc.", data.hash[:8])
			}
		}
	} else {
		if fuzzer.Config.Debug && (len(data.rawCover) > 0 || data.bugCount > 0) {
			fuzzer.Logf(2, "UCB Worker: Prog %s (Non-Corpus), basic stats updated. Δcov: %d.", data.hash[:8], deltaCovLen)
		}
	}
}
