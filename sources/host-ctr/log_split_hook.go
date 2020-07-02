package host_ctr

import (
	"io"
	"io/ioutil"
	"os"

	"github.com/containerd/containerd/log"
	"github.com/sirupsen/logrus"
)
// UseLogSplitHook configures the default logger to write error and fatal
// messages to stderr and the remainder to stdout.
func UseLogSplitHook() {
	useLogSplitHook(log.L.Logger)
}

// useLogSplitHook configures the provided logger to write error and fatal
// messages to stderr and the remainder to stdout.
func useLogSplitHook(logger *logrus.Logger) {
	logger.SetOutput(ioutil.Discard)
	logger.AddHook(&LogSplitHook{os.Stdout, []logrus.Level{
		logrus.WarnLevel, logrus.InfoLevel, logrus.DebugLevel, logrus.TraceLevel}})
	logger.AddHook(&LogSplitHook{os.Stderr, []logrus.Level{
		logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel}})
}

// LogSplitHook is expected to implement the correct logrus interface.
var _ logrus.Hook = (*LogSplitHook)(nil)

// LogSplitHook directs matched levels to its configured output.
type LogSplitHook struct {
	output io.Writer
	levels []logrus.Level
}

// Fire is invoked when logrus tries to log any message.
func (hook *LogSplitHook) Fire(entry *logrus.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}
	for _, level := range hook.levels {
		if level == entry.Level {
			_, err := hook.output.Write([]byte(line))
			return err
		}
	}
	return nil
}

// Returns the log levels this hook is being applied to
func (hook *LogSplitHook) Levels() []logrus.Level {
	return hook.levels
}
