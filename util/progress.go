package util

import (
	"time"

	"github.com/briandowns/spinner"
	pb "gopkg.in/cheggaaa/pb.v1"
)

var (
	// Quiet :
	Quiet = false
)

// Spinner :
type Spinner struct {
	client *spinner.Spinner
}

// NewSpinner :
func NewSpinner(suffix string) *Spinner {
	if Quiet {
		return &Spinner{}
	}
	s := spinner.New(spinner.CharSets[36], 100*time.Millisecond)
	s.Suffix = suffix
	return &Spinner{client: s}
}

// Start :
func (s *Spinner) Start() {
	if s.client == nil {
		return
	}
	s.client.Start()
}

// Stop :
func (s *Spinner) Stop() {
	if s.client == nil {
		return
	}
	s.client.Stop()
}

// ProgressBar :
type ProgressBar struct {
	client *pb.ProgressBar
}

// PbStartNew :
func PbStartNew(total int) *ProgressBar {
	if Quiet {
		return &ProgressBar{}
	}
	bar := pb.StartNew(total)
	return &ProgressBar{client: bar}
}

// Increment :
func (p *ProgressBar) Increment() {
	if p.client == nil {
		return
	}
	p.client.Increment()
}

// Finish :
func (p *ProgressBar) Finish() {
	if p.client == nil {
		return
	}
	p.client.Finish()
}
