package main

import (
	"fmt"
	"time"
)

func main() {
	for i := 0; i < 1000; i++ {
		helloWorld(i)
		time.Sleep(time.Second)
	}
}

//go:noinline
func helloWorld(i int) {
	fmt.Println("helloWorld", i)
}
