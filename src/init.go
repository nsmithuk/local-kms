package src

import (
	log "github.com/sirupsen/logrus"
)

var logger = log.New()

func init() {

	//logger.SetLevel(log.DebugLevel)
	logger.SetFormatter(&log.TextFormatter{
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05.000",
	})

}
