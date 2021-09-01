//go:build linux
// +build linux

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

var (
	flagPid    = flag.Int("pid", 0, "pid of program to attach to")
	flagSymbol = flag.String("symbol", "main.helloWorld", "symbol to attach to")
	flagOffset = flag.Int("offset", 0, "offset override")
)

func main() {
	flag.Parse()

	// Increase rlimit so the eBPF map and program can be loaded.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}

	uprobeObj, err := ioutil.ReadFile("bpf/uprobe.bpf.o")
	if err != nil {
		log.Fatalf("failed to read uprobe bpf object file")
	}

	rp := runParams{
		Reader: bytes.NewReader(uprobeObj),
		Pid:    *flagPid,
		Symbol: *flagSymbol,
		Offset: *flagOffset,
	}
	p, err := newUprobe(rp)
	if err != nil {
		log.Fatal("failed to load uprobe: ", err)
	}
	defer p.Stop()

	// If we got here, then the probe was installed, wait for a signal.
	log.Printf("Success!")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
}

type runParams struct {
	Reader io.ReaderAt
	Pid    int
	Symbol string
	Offset int
	Path   string
}

type probe struct {
	spec     *ebpf.CollectionSpec
	programs struct {
		Uprobe *ebpf.Program `ebpf:"uprobe"`
	}
	ex   *link.Executable
	link link.Link
}

func newUprobe(rp runParams) (*probe, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(rp.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection spec from reader: %v", err)
	}

	p := &probe{spec: spec}
	if err := spec.LoadAndAssign(&p.programs, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("failed to load ebpf program: %w", err)
	}

	absPath, err := filepath.Abs("helloworld/helloworld")
	if err != nil {
		return nil, fmt.Errorf("invalid path %q: %w", rp.Path, err)
	}

	p.ex, err = link.OpenExecutable(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open executable: %w", err)
	}

	opts := &link.UprobeOptions{
		Offset: uint64(*flagOffset),
		PID:    rp.Pid,
	}
	p.link, err = p.ex.Uprobe(rp.Symbol, p.programs.Uprobe, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to attach uprobe: %w", err)
	}

	return p, nil
}

func (p *probe) Stop() error {
	return p.link.Close()
}
