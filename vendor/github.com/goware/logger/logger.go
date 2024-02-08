package logger

import (
	"fmt"
	"log"
	"os"
)

type Logger interface {
	With(args ...interface{}) Logger
	Debug(v ...interface{})
	Debugf(format string, v ...interface{})
	Info(v ...interface{})
	Infof(format string, v ...interface{})
	Warn(v ...interface{})
	Warnf(format string, v ...interface{})
	Error(v ...interface{})
	Errorf(format string, v ...interface{})
	Fatal(v ...interface{})
	Fatalf(format string, v ...interface{})
}

type StdLogger interface {
	Fatal(v ...interface{})
	Fatalf(format string, v ...interface{})
	Print(v ...interface{})
	Println(v ...interface{})
	Printf(format string, v ...interface{})
}

type Level uint8

const (
	LogLevel_DEBUG Level = iota
	LogLevel_INFO
	LogLevel_WARN
	LogLevel_ERROR
	LogLevel_FATAL
)

var (
	_ Logger    = &StdLogAdapter{}
	_ StdLogger = &StdLogAdapter{}
)

type StdLogAdapter struct {
	Level Level
	out   *log.Logger
	attrs string
}

func NewLogger(level Level) Logger {
	return &StdLogAdapter{out: log.New(os.Stdout, "", 0), Level: level}
}

func (s *StdLogAdapter) With(args ...interface{}) Logger {
	if len(args) == 0 {
		return s
	}
	if len(args)%2 != 0 {
		return s
	}
	attrs := ""
	for i := 0; i < len(args); i += 2 {
		k := args[i]
		v := args[i+1]
		attrs += fmt.Sprintf("%s:%v", k, v)
		if i+2 < len(args) {
			attrs += ", "
		}
	}
	out := &StdLogAdapter{Level: s.Level, out: s.out, attrs: fmt.Sprintf("[%s]", attrs)}
	return out
}

func (s *StdLogAdapter) Debug(v ...interface{}) {
	if s.Level <= LogLevel_DEBUG {
		if s.attrs != "" {
			s.Println(append([]interface{}{"[DEBUG]"}, append([]interface{}{s.attrs}, v...)...)...)
		} else {
			s.Println(append([]interface{}{"[DEBUG]"}, v...)...)
		}
	}
}

func (s *StdLogAdapter) Debugf(format string, v ...interface{}) {
	if s.Level <= LogLevel_DEBUG {
		if s.attrs != "" {
			s.Printf(fmt.Sprintf("[DEBUG] %v %s", s.attrs, format), v...)
		} else {
			s.Printf(fmt.Sprintf("[DEBUG] %s", format), v...)
		}
	}
}

func (s *StdLogAdapter) Info(v ...interface{}) {
	if s.Level <= LogLevel_INFO {
		if s.attrs != "" {
			s.Println(append([]interface{}{"[INFO]"}, append([]interface{}{s.attrs}, v...)...)...)
		} else {
			s.Println(append([]interface{}{"[INFO]"}, v...)...)
		}
	}
}

func (s *StdLogAdapter) Infof(format string, v ...interface{}) {
	if s.Level <= LogLevel_INFO {
		if s.attrs != "" {
			s.Printf(fmt.Sprintf("[INFO] %v %s", s.attrs, format), v...)
		} else {
			s.Printf(fmt.Sprintf("[INFO] %s", format), v...)
		}
	}
}

func (s *StdLogAdapter) Warn(v ...interface{}) {
	if s.Level <= LogLevel_WARN {
		if s.attrs != "" {
			s.Println(append([]interface{}{"[WARN]"}, append([]interface{}{s.attrs}, v...)...)...)
		} else {
			s.Println(append([]interface{}{"[WARN]"}, v...)...)
		}
	}
}

func (s *StdLogAdapter) Warnf(format string, v ...interface{}) {
	if s.Level <= LogLevel_WARN {
		if s.attrs != "" {
			s.Printf(fmt.Sprintf("[WARN] %v %s", s.attrs, format), v...)
		} else {
			s.Printf(fmt.Sprintf("[WARN] %s", format), v...)
		}
	}
}

func (s *StdLogAdapter) Error(v ...interface{}) {
	if s.Level <= LogLevel_ERROR {
		if s.attrs != "" {
			s.Println(append([]interface{}{"[ERROR]"}, append([]interface{}{s.attrs}, v...)...)...)
		} else {
			s.Println(append([]interface{}{"[ERROR]"}, v...)...)
		}
	}
}

func (s *StdLogAdapter) Errorf(format string, v ...interface{}) {
	if s.Level <= LogLevel_ERROR {
		if s.attrs != "" {
			s.Printf(fmt.Sprintf("[ERROR] %v %s", s.attrs, format), v...)
		} else {
			s.Printf(fmt.Sprintf("[ERROR] %s", format), v...)
		}
	}
}

func (s *StdLogAdapter) Fatal(v ...interface{}) {
	if s.attrs != "" {
		s.Println(append([]interface{}{"[FATAL]"}, append([]interface{}{s.attrs}, v...)...)...)
	} else {
		s.Println(append([]interface{}{"[FATAL]"}, v...)...)
	}
	os.Exit(1)
}

func (s *StdLogAdapter) Fatalf(format string, v ...interface{}) {
	if s.attrs != "" {
		s.Printf(fmt.Sprintf("[FATAL] %v %s", s.attrs, format), v...)
	} else {
		s.Printf(fmt.Sprintf("[FATAL] %s", format), v...)
	}
	os.Exit(1)
}

func (s *StdLogAdapter) Print(v ...interface{}) {
	s.out.Print(v...)
}

func (s *StdLogAdapter) Println(v ...interface{}) {
	s.out.Println(v...)
}

func (s *StdLogAdapter) Printf(format string, v ...interface{}) {
	s.out.Printf(format, v...)
}

func Nop() Logger {
	return &nop{}
}

type nop struct{}

func (n *nop) With(args ...interface{}) Logger        { return n }
func (n *nop) Debug(v ...interface{})                 {}
func (n *nop) Debugf(format string, v ...interface{}) {}
func (n *nop) Info(v ...interface{})                  {}
func (n *nop) Infof(format string, v ...interface{})  {}
func (n *nop) Warn(v ...interface{})                  {}
func (n *nop) Warnf(format string, v ...interface{})  {}
func (n *nop) Error(v ...interface{})                 {}
func (n *nop) Errorf(format string, v ...interface{}) {}
func (n *nop) Fatal(v ...interface{})                 {}
func (n *nop) Fatalf(format string, v ...interface{}) {}
