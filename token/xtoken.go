package xtoken

type xtoken struct {
	token chan struct{}
}

// New 新建一个令牌分发
func New(n int) *xtoken {
	var x xtoken
	x.token = make(chan struct{}, n)
	return &x
}

func (x *xtoken) Add() {
	x.token <- struct{}{}
}

func (x *xtoken) Done() {
	<-x.token
}
