package migration

import (
	"fmt"
)

type Result struct {
	RowsAffected   int
	Logs           map[string][]string
	ItemsProcessed []string
	Errors         map[string]error
}

func NewResult() *Result {
	return &Result{
		Logs:   make(map[string][]string),
		Errors: make(map[string]error),
	}
}

func (r *Result) AddItem(item string) {
	r.ItemsProcessed = append(r.ItemsProcessed, item)
	r.RowsAffected++
}

func (r *Result) Errorf(item string, format string, args ...interface{}) {
	r.Errors[item] = fmt.Errorf(format, args...)
}

func (r *Result) Log(item string, logEntry string) {
	r.Logs[item] = append(r.Logs[item], logEntry)
}

func (r *Result) Logf(item string, format string, a ...interface{}) {
	r.Logs[item] = append(r.Logs[item], fmt.Sprintf(format, a...))
}
