package analyzer

import (
	"context"
	"log"
	"sync"

	"github.com/voxire/lint-in-the-dead/pkg/models"
)

// WorkItem wraps a job destined for the pool.
type WorkItem struct {
	Job      models.Job
	ResultCh chan<- models.AnalysisResult
}

// Pool is a fixed-size goroutine pool for running analysis jobs.
type Pool struct {
	workers int
	jobs    chan WorkItem
	wg      sync.WaitGroup
	analyzer *Analyzer
}

func NewPool(ctx context.Context, workers int, a *Analyzer) *Pool {
	p := &Pool{
		workers:  workers,
		jobs:     make(chan WorkItem, workers*4),
		analyzer: a,
	}
	for i := range workers {
		p.wg.Add(1)
		go p.work(ctx, i)
	}
	return p
}

func (p *Pool) Submit(item WorkItem) {
	p.jobs <- item
}

func (p *Pool) Stop() {
	close(p.jobs)
	p.wg.Wait()
}

func (p *Pool) work(ctx context.Context, id int) {
	defer p.wg.Done()
	for {
		select {
		case item, ok := <-p.jobs:
			if !ok {
				return
			}
			log.Printf("worker-%d: processing job %s", id, item.Job.ID)
			result, err := p.analyzer.Run(ctx, item.Job)
			if err != nil {
				log.Printf("worker-%d: job %s error: %v", id, item.Job.ID, err)
				result = models.AnalysisResult{JobID: item.Job.ID}
			}
			if item.ResultCh != nil {
				item.ResultCh <- result
			}
		case <-ctx.Done():
			return
		}
	}
}
