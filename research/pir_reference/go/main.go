// Adapter only: all PIR cryptography is the pinned, unmodified upstream library.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	pir "github.com/ahenzinger/simplepir/pir"
	"os"
	"runtime"
	"time"
)

func main() {
	count := flag.Uint64("count", 10000, "64 bit records")
	trials := flag.Uint64("trials", 30, "independent setup trials")
	queries := flag.Uint64("queries", 16, "queries per trial")
	seed := flag.Uint64("seed", 9001, "public index workload seed")
	output := flag.String("output", "", "new JSONL file")
	flag.Parse()
	if *count == 0 || *count > 1000000 || *trials == 0 || *trials > 1000 || *queries == 0 || *queries > 10000 || *output == "" {
		panic("bounded count/trials/queries and output required")
	}
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	emit := func(row map[string]interface{}) {
		if err := encoder.Encode(row); err != nil {
			panic(err)
		}
	}
	runtime.GOMAXPROCS(1)
	pi := pir.SimplePIR{}
	params := pi.PickParams(*count, 64, 1024, 32)
	values := make([]uint64, *count)
	for i := range values {
		values[i] = uint64(i)*0x9e3779b97f4a7c15 + 17
	}
	for trial := uint64(0); trial < *trials; trial++ {
		runtime.GC()
		start := time.Now()
		db := pir.MakeDB(*count, 64, &params, values)
		dbNS := time.Since(start).Nanoseconds()
		start = time.Now()
		shared := pi.Init(db.Info, params)
		initNS := time.Since(start).Nanoseconds()
		start = time.Now()
		server, hint := pi.Setup(db, shared, params)
		setupNS := time.Since(start).Nanoseconds()
		emit(map[string]interface{}{"kind": "setup", "trial": trial, "database_build_ns": dbNS, "shared_init_ns": initNS, "preprocessing_ns": setupNS, "offline_upload_bytes": shared.Data[0].Size() * 4, "offline_download_bytes": hint.Size() * 4, "logical_database_bytes": *count * 8, "server_matrix_bytes": db.Data.Size() * 4, "l": params.L, "m": params.M, "lwe_n": params.N, "logq": params.Logq, "p": params.P, "sigma": params.Sigma, "hint_elements": hint.Size()})
		// Warm up the real online path; exclude this sample from measurements.
		state, q := pi.Query(0, shared, params, db.Info)
		answer := pi.Answer(db, pir.MsgSlice{Data: []pir.Msg{q}}, server, shared, params)
		if pi.Recover(0, 0, hint, q, answer, shared, state, params, db.Info) != values[0] {
			panic("warm-up oracle mismatch")
		}
		for query := uint64(0); query < *queries; query++ {
			index := ((trial**queries+query)*7919 + *seed) % *count
			start = time.Now()
			client, q := pi.Query(index, shared, params, db.Info)
			queryNS := time.Since(start).Nanoseconds()
			start = time.Now()
			answer := pi.Answer(db, pir.MsgSlice{Data: []pir.Msg{q}}, server, shared, params)
			answerNS := time.Since(start).Nanoseconds()
			start = time.Now()
			value := pi.Recover(index, 0, hint, q, answer, shared, client, params, db.Info)
			recoverNS := time.Since(start).Nanoseconds()
			if value != values[index] {
				panic(fmt.Sprintf("oracle mismatch trial%d query%d", trial, query))
			}
			emit(map[string]interface{}{"kind": "query", "trial": trial, "query": query, "generation_ns": queryNS, "server1_ns": answerNS, "server2_ns": 0, "recovery_ns": recoverNS, "query_payload_bytes": q.Size() * 4, "response_payload_bytes": answer.Size() * 4, "database_payload_bytes_per_server": *count * 8, "server_matrix_bytes_scanned": db.Data.Size() * 4, "correct": true})
		}
	}
	if err := file.Sync(); err != nil {
		panic(err)
	}
}
