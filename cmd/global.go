package cmd

import (
	"github.com/spf13/cobra"
)

const (
	loggerTypeStdout = 0
	loggerTypeFile   = 1
	loggerTypeTcp    = 2
)

type GlobalFlags struct {
	Ifname      string
	ContainerID string
}

func getGlobalConf(command *cobra.Command) (conf GlobalFlags, err error) {
	conf.ContainerID, err = command.Flags().GetString("containerID")
	if err != nil {
		return
	}
	conf.Ifname, err = command.Flags().GetString("ifname")
	if err != nil {
		return
	}
	return conf, nil
}
