package cmd

import (
	"cacapture/user/config"
	"cacapture/user/module"
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
)

var rc = config.Config{}

var rootCmd = &cobra.Command{
	Use:   "cacapture",
	Short: "Capture and analyze the container's network traffic",
	Long:  `Capture and analyze the container's network traffic`,
	Run:   cacaptureCommandFunc,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&rc.ContainerID, "containerID", "", "containerID")
	rootCmd.PersistentFlags().StringVar(&rc.Ifname, "ifname", "", "ifname")
}

func getConf(command *cobra.Command) (conf config.Config, err error) {
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
func cacaptureCommandFunc(cmd *cobra.Command, args []string) {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFun := context.WithCancel(context.Background())

	logger := log.New(os.Stdout, "cacapture: ", log.LstdFlags)
	conf, err := getConf(cmd)
	if err != nil {
		logger.Println("Error:", err)
		return
	}

	logger.Printf("CACAPTURE:: Pid Info: %d", os.Getpid())

	var modNames=[]string{module.IModule}

	var runMods unit8
	var runModules =make(map[string]module.IModule)
	var wg sync.WaitGroup
	for _, modName := range modNames {
		mod :=module.GetModuleByName(modName)
		if mod==nil{
			logger.Printf("Module %s not found",modName)
			break
		}

		logger.Printf("%s\tmodule initialization", mod.Name())

		err = mod.Init(ctx,logger,&conf)
		if err!=nil{
			logger.Printf("Module %s init failed: %v",mod.Name(),err)
			continue
		}

		err = mod.Run()


}
