package limitwaitgroup

import (
	"fmt"
	"testing"
	"time"
)

func work() {
	fmt.Println("11111111")
	time.Sleep(time.Second * 2)
}

func TestLimitGo(t *testing.T) {
	lwg := New(5)
	for i := 0; i < 20; i++ {
		lwg.Add()
		go func() { work(); lwg.Done() }()
	}

	lwg.Wait()
}
