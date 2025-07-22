// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"encoding/json"
	"reflect"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"

)

func main() {
	var (
		flagVersion = flag.Uint64("version", 0, "database version")
		flagOS      = flag.String("os", runtime.GOOS, "target OS")
		flagArch    = flag.String("arch", runtime.GOARCH, "target arch")
	)
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
	}
	if args[0] == "bench" {
		if len(args) != 2 {
			usage()
		}
		target, err := prog.GetTarget(*flagOS, *flagArch)
		if err != nil {
			tool.Failf("failed to find target: %v", err)
		}
		bench(target, args[1])
		return
	}
	var target *prog.Target
	if *flagOS != "" || *flagArch != "" {
		var err error
		target, err = prog.GetTarget(*flagOS, *flagArch)
		if err != nil {
			tool.Failf("failed to find target: %v", err)
		}
	}
	switch args[0] {
	case "pack":
		if len(args) != 3 {
			usage()
		}
		pack(args[1], args[2], target, *flagVersion)
	case "unpack":
		if len(args) != 3 {
			usage()
		}
		unpack(args[1], args[2], target)
	case "merge":
		if len(args) < 3 {
			usage()
		}
		merge(args[1], args[2:], target)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: syz-db can be used to manipulate corpus
databases that are used by syz-managers. The following generic arguments are
offered:
  -arch string
  -os string
  -version uint
  -vv int

  they can be used for:
  packing a database:
    syz-db pack dir corpus.db
  unpacking a database. A file containing performed syscalls will be returned:
    syz-db unpack corpus.db dir
  merging databases. No additional file will be created: The first file will be replaced by the merged result:
    syz-db merge dst-corpus.db add-corpus.db* add-prog*
  running a deserialization benchmark and printing corpus stats:
    syz-db bench corpus.db
`)
	os.Exit(1)
}

func pack(dir, file string, target *prog.Target, version uint64) {
	files, err := os.ReadDir(dir)
	if err != nil {
		tool.Failf("failed to read dir: %v", err)
	}
	var records []db.Record
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			tool.Failf("failed to read file %v: %v", file.Name(), err)
		}
		var seq uint64
		key := file.Name()
		if parts := strings.Split(file.Name(), "-"); len(parts) == 2 {
			var err error
			if seq, err = strconv.ParseUint(parts[1], 10, 64); err == nil {
				key = parts[0]
			}
		}
		if sig := hash.String(data); key != sig {
			if target != nil {
				p, err := target.Deserialize(data, prog.NonStrict)
				if err != nil {
					tool.Failf("failed to deserialize %v: %v", file.Name(), err)
				}
				data = p.Serialize()
				sig = hash.String(data)
			}
			fmt.Fprintf(os.Stderr, "fixing hash %v -> %v\n", key, sig)
			key = sig
		}
		records = append(records, db.Record{
			Val: data,
			Seq: seq,
		})
	}
	if err := db.Create(file, version, records); err != nil {
		tool.Fail(err)
	}
}

// Define types outside the function
type ArgInfo struct {
    Type    string      `json:"type"`
    Val     interface{} `json:"value,omitempty"`
    SubArgs []ArgInfo   `json:"sub_args,omitempty"`
}

type CallInfo struct {
    Name string    `json:"name"`
    Args []ArgInfo `json:"args"`
}

type ProgramAST struct {
    Calls    []CallInfo `json:"calls"`
    Comments []string   `json:"comments,omitempty"`
}

func unpack(file, dir string, target *prog.Target) {
    // Open database file
    db, err := db.Open(file, false)
    if err != nil {
        tool.Failf("failed to open database: %v", err)
    }

    // Create target directory
    osutil.MkdirAll(dir)
    astDir := filepath.Join(dir, "AST_")
    osutil.MkdirAll(astDir)

    // Create type analysis file
    targetFile, err := os.Create("target")
    if err != nil {
        tool.Failf("failed to create target file: %v", err)
    }
    defer targetFile.Close()

    for key, rec := range db.Records {
        fname := filepath.Join(dir, key)
        if rec.Seq != 0 {
            fname += fmt.Sprintf("-%v", rec.Seq)
        }

        if err := osutil.WriteFile(fname, rec.Val); err != nil {
            tool.Failf("failed to output file: %v", err)
        }

        if target != nil {
            p, err := target.Deserialize(rec.Val, prog.NonStrict)
            if err != nil {
                tool.Failf("failed to deserialize record %v: %v", key, err)
            }

            baseFileName := filepath.Join(astDir, key)
            if rec.Seq != 0 {
                baseFileName += fmt.Sprintf("-%v", rec.Seq)
            }

            // Recursive function to process arguments
            var processArg func(arg prog.Arg) ArgInfo
            processArg = func(arg prog.Arg) ArgInfo {
                if arg == nil {
                    return ArgInfo{}
                }

                info := ArgInfo{
                    Type: reflect.TypeOf(arg).String(),
                }

                switch a := arg.(type) {
                case *prog.ConstArg:
                    info.Val = a.Val
                case *prog.DataArg:
                    if a.Dir() != prog.DirOut {
                        info.Val = fmt.Sprintf("%x", a.Data())
                    }
                case *prog.GroupArg:
                    info.SubArgs = make([]ArgInfo, len(a.Inner))
                    for i, inner := range a.Inner {
                        info.SubArgs[i] = processArg(inner)
                    }
                case *prog.PointerArg:
                    info.Val = a.Address
                    if a.Res != nil {
                        resInfo := processArg(a.Res)
                        info.SubArgs = []ArgInfo{resInfo}
                    }
                case *prog.UnionArg:
                    if a.Option != nil {
                        info.SubArgs = []ArgInfo{processArg(a.Option)}
                    }
                case *prog.ResultArg:
                    info.Val = a.Val
                    if a.Res != nil {
                        info.Val = fmt.Sprintf("ref=%v", a.Res.Val)
                    }
                }
                return info
            }

            // Create AST structure
            ast := ProgramAST{
                Calls:    make([]CallInfo, len(p.Calls)),
                Comments: p.Comments,
            }

            // Process each call
            for i, call := range p.Calls {
                callInfo := CallInfo{
                    Name: call.Meta.Name,
                }

                // Process arguments
                callInfo.Args = make([]ArgInfo, len(call.Args))
                for j, arg := range call.Args {
                    callInfo.Args[j] = processArg(arg)
                }

                ast.Calls[i] = callInfo
            }

            // Write type information to target file
            typeInfo := fmt.Sprintf("Program Analysis for %s:\n", key)
            typeInfo += fmt.Sprintf("Number of Calls: %d\n", len(p.Calls))
            typeInfo += fmt.Sprintf("Has Comments: %v\n", len(p.Comments) > 0)
            targetFile.WriteString(typeInfo + "\n---\n")

            // Write JSON format
            jsonFileName := baseFileName + ".json"
            jsonData, err := json.MarshalIndent(ast, "", "  ")
            if err != nil {
                tool.Failf("failed to marshal JSON: %v", err)
            }
            if err := osutil.WriteFile(jsonFileName, jsonData); err != nil {
                tool.Failf("failed to write JSON file: %v", err)
            }

            // Removed text file writing logic
        }
    }
}

func merge(file string, adds []string, target *prog.Target) {
	dstDB, err := db.Open(file, false)
	if err != nil {
		tool.Failf("failed to open database: %v", err)
	}
	for _, add := range adds {
		if addDB, err := db.Open(add, false); err == nil {
			for key, rec := range addDB.Records {
				dstDB.Save(key, rec.Val, rec.Seq)
			}
			continue
		} else if target == nil {
			tool.Failf("failed to open db %v: %v", add, err)
		}
		data, err := os.ReadFile(add)
		if err != nil {
			tool.Fail(err)
		}
		if _, err := target.Deserialize(data, prog.NonStrict); err != nil {
			tool.Failf("failed to deserialize %v: %v", add, err)
		}
		dstDB.Save(hash.String(data), data, 0)
	}
	if err := dstDB.Flush(); err != nil {
		tool.Failf("failed to save db: %v", err)
	}
}

func bench(target *prog.Target, file string) {
	start := time.Now()
	db, err := db.Open(file, false)
	if err != nil {
		tool.Failf("failed to open database: %v", err)
	}
	var corpus []*prog.Prog
	for _, rec := range db.Records {
		p, err := target.Deserialize(rec.Val, prog.NonStrict)
		if err != nil {
			tool.Failf("failed to deserialize: %v\n%s", err, rec.Val)
		}
		corpus = append(corpus, p)
	}
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	fmt.Printf("allocs %v MB (%v M), next GC %v MB, sys heap %v MB, live allocs %v MB (%v M), time %v\n",
		stats.TotalAlloc>>20,
		stats.Mallocs>>20,
		stats.NextGC>>20,
		stats.HeapSys>>20,
		stats.Alloc>>20,
		(stats.Mallocs-stats.Frees)>>20,
		time.Since(start))
	n := len(corpus)
	fmt.Printf("corpus size: %v\n", n)
	if n == 0 {
		return
	}
	sum := 0
	lens := make([]int, n)
	for i, p := range corpus {
		sum += len(p.Calls)
		lens[i] = len(p.Calls)
	}
	sort.Ints(lens)
	fmt.Printf("program size: min=%v avg=%v max=%v 10%%=%v 50%%=%v 90%%=%v\n",
		lens[0], sum/n, lens[n-1], lens[n/10], lens[n/2], lens[n*9/10])
}

