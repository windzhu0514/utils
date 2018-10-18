package limitwaitgroup

import (
	"sync"
)

type Limitwaitgroup struct {
	sem chan struct{}
	wg  sync.WaitGroup
}

func New(n int) *Limitwaitgroup {
	return &Limitwaitgroup{
		sem: make(chan struct{}, n),
	}
}

func (l *Limitwaitgroup) Add() {
	l.sem <- struct{}{}
	l.wg.Add(1)
}

func (l *Limitwaitgroup) Done() {
	<-l.sem
	l.wg.Done()
}

func (l *Limitwaitgroup) Wait() {
	l.wg.Wait()
}
