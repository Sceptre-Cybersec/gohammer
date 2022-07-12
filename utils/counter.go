package utils

import "sync"

var counterAvg []int

type Counter struct {
	counter     int
	counterPrev int
	counterLock sync.Mutex
	counterAvg  []int

	errorCounter     int
	errorCounterLock sync.Mutex
}

func NewCounter() *Counter {
	return new(Counter)
}

func (c *Counter) GetCountNum() int {
	return c.counter
}

func (c *Counter) UpdateAvg() {
	c.counterAvg = append(c.counterAvg, c.counter-c.counterPrev)
	c.counterPrev = c.counter
	//use 3 second average
	if len(c.counterAvg) > 3 {
		c.counterAvg = c.counterAvg[1:]
	}
}

func (c *Counter) GetCountAvg() int {
	avg := 0
	sum := 0
	for _, c := range c.counterAvg {
		sum += c
	}
	if len(c.counterAvg) > 0 {
		avg = sum / len(c.counterAvg)
	} else {
		avg = c.GetCountNum()
	}
	return avg
}

func (c *Counter) GetErrorNum() int {
	return c.errorCounter
}

func (c *Counter) Reset() {
	c.counterLock.Lock()
	c.counter = 0
	c.counterLock.Unlock()
}

// CounterInc increments the request progress counter
func (c *Counter) CounterInc() {
	c.counterLock.Lock()
	c.counter++
	c.counterLock.Unlock()
}

// ErrorCounterInc increments the request error counter whenever a request fails
func (c *Counter) ErrorCounterInc() {
	c.errorCounterLock.Lock()
	c.errorCounter++
	c.errorCounterLock.Unlock()
}
