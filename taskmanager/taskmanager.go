package taskmanager

import (
	"errors"
	"sync"

	"github.com/robfig/cron/v3"
)

type Task interface {
	Init() error
	Run(ctx JobContext)
	Worker(ctx JobContext)
	Release() error
}
type TaskOptions struct {
	WorkerNum      int
	CronExpression string
	StartNow       bool
}

type taskManager struct {
	mux  sync.Mutex
	jobs map[string]*Job
	Cron *cron.Cron
}

type TaskStatus int

const (
	StatusStopped TaskStatus = iota
	StatusStopping
	StatusRunning
	StatusWaiting
)

type Job struct {
	JobContext

	opts    TaskOptions
	task    Task
	status  TaskStatus
	entryID cron.EntryID

	wgWorker sync.WaitGroup
}

type JobContext struct {
	Key  string
	Stop chan struct{}
}

var manager taskManager

// Run implements cron Job interface
func (job *Job) Run() {
	if err := job.task.Init(); err != nil {
		return
	}

	for i := 0; i < job.opts.WorkerNum; i++ {
		job.wgWorker.Add(1)
		go func() {
			job.task.Worker(job.JobContext)
			job.wgWorker.Done()
		}()
	}

	job.task.Run(job.JobContext)
	job.wgWorker.Wait()
	delete(manager.jobs, job.JobContext.Key)
}

func Start(key string, opts TaskOptions, task Task) error {
	_, ok := getJob(key)
	if ok {
		return errors.New("task is already registered")
	}

	job := &Job{opts: opts, task: task}

	if job.status != StatusStopped {
		return errors.New("task is already running")
	}

	// 定时任务
	if job.opts.CronExpression != "" {
		if manager.Cron == nil {
			manager.Cron = cron.New(cron.WithChain(cron.SkipIfStillRunning(nil))) // TODO:
			manager.Cron.Start()
		}

		entryID, err := manager.Cron.AddJob(job.opts.CronExpression, job)
		if err != nil {
			return err
		}

		job.entryID = entryID

		if job.opts.StartNow {
			job.Run()
		}

		return nil
	}

	go job.Run()

	manager.jobs[key] = job

	return nil
}

func Stop(key string) error {
	job, ok := getJob(key)
	if !ok {
		return errors.New("task is already stopped")
	}

	if job.status != StatusRunning {
		return errors.New("task is not running")
	}

	close(job.Stop)
	return nil
}

func Status(key string) TaskStatus {
	job, ok := getJob(key)
	if !ok {
		return StatusStopped
	}

	return job.status
}

func IncreaseWorker(key string) error {
	job, ok := getJob(key)
	if !ok {
		return errors.New("task is not running")
	}

	if job.status != StatusRunning {
		return errors.New("task is not running")
	}

	job.wgWorker.Add(1)
	job.opts.WorkerNum++
	go func() {
		job.task.Worker(job.JobContext)
		job.wgWorker.Done()
	}()

	return nil
}

func DecreaseWorker(key string) error {
	job, ok := getJob(key)
	if !ok {
		return errors.New("task is not running")
	}

	if job.status != StatusRunning {
		return errors.New("task is not running")
	}

	job.status = StatusStopping

	go func() { job.Stop <- struct{}{} }()

	return nil
}

func getJob(key string) (*Job, bool) {
	_, ok := manager.jobs[key]
	if !ok {
		return nil, false
	}

	manager.mux.Lock()
	defer manager.mux.Unlock()

	job, ok := manager.jobs[key]
	if !ok {
		return nil, false
	}

	return job, true
}
