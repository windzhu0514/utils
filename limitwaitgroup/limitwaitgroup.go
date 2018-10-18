package limitwaitgroup

import (
	"sync"
)

type Limitwaitgroup struct {
	sem chan struct{}
	mux sync.Mutex
	wg  sync.WaitGroup
}

func New(n int) *Limitwaitgroup {
	return &Limitwaitgroup{
		sem: make(chan struct{}, n),
	}
}

func (l *Limitwaitgroup) Add(delta int) {
	l.sem <- struct{}{}
	l.mux.Lock()
	defer l.mux.Unlock()
	l.wg.Add(delta)
}

func (l *Limitwaitgroup) Done() {
	<-l.sem
	l.mux.Lock()
	defer l.mux.Unlock()
	l.wg.Done()
}

func (l *Limitwaitgroup) Wait() {
	l.mux.Lock()
	defer l.mux.Unlock()
	l.wg.Wait()
}
