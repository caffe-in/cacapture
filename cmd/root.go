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

	_ "net/http/pprof"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netns"
)

const (
	defaultPid uint64 = 0
	defaultUid uint64 = 0
)

var rc = &config.ContainerConfig{}
var OrignalNsHandle netns.NsHandle

var rootCmd = &cobra.Command{
	Use:   "cacapture",
	Short: "Capture and analyze the container's network traffic",
	Long:  `Capture and analyze the container's network traffic`,
	Run:   cacaptureCommandFunc,
}

func init() {
	rootCmd.PersistentFlags().IntVar(&rc.PerCpuMapSize, "mapsize", 2048, "eBPF map size per CPU,for events buffer. default:1024 * PAGESIZE. (KB)")
	rootCmd.PersistentFlags().StringVar(&rc.Mode, "Mode", "Containerd", "the mode for which container will be monitor, Docker or Containerd")
	rootCmd.PersistentFlags().StringVar(&rc.ContainerID, "ContainerID", "", "the container ID which container is monitored")
	rootCmd.PersistentFlags().StringSliceVar(&rc.PodName, "PodName", []string{}, "the pod's name or pod lists name which we will monitor")
	rootCmd.PersistentFlags().StringVar(&rc.PodNsName, "PodNsName", "default", "the pod's ns name for the pod in")
	rootCmd.PersistentFlags().StringVar(&rc.Ifname, "Ifname", "", "ifname")
	rootCmd.PersistentFlags().StringVar(&rc.PcapFile, "PcapFile", "capture_msg/test.pcapng", "pcapngFilename")
	rootCmd.PersistentFlags().BoolVar(&rc.SentNet, "Sentnet", false, "sent_net")
	rootCmd.PersistentFlags().StringVar(&rc.DstIP, "DstIP", "172.16.8.64", "dstIP")
	rootCmd.PersistentFlags().IntVar(&rc.DstPort, "DstPort", 4789, "dstPort")

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
	if rc.Mode != "Docker" && rc.Mode != "Containerd" {
		logger.Printf("only support container runtime for docker and containerd, please input the mode with Docker or Containerd")
		os.Exit(0)
	}

	logger.Printf("cacapture pid info: %d", os.Getpid())

	var modNames = []string{module.ModuleNameContainer, module.ModuleNameContainerState}

	var runMods uint8
	var runModules = make(map[string]module.IModule)
	var wg sync.WaitGroup

	for _, modName := range modNames {
		mod := module.GetModuleByName(modName)
		if mod == nil {
			logger.Printf("module %s not found", modName)
			break
		}

		logger.Printf("%s\tmodule initialization", mod.Name())
		var conf config.IConfig

		conf = rc
		conf.SetPerCpuMapSize(rc.PerCpuMapSize)
		err := mod.Init(ctx, logger, conf)

		if err != nil {
			logger.Printf("Module %s init failed: %v", mod.Name(), err)
			continue
		}

		err = mod.Run()
		if err != nil {
			logger.Printf("%s\tmodule run failed, [skip it]. error:%+v", mod.Name(), err)
			continue
		}

		runModules[mod.Name()] = mod
		logger.Printf("%s\tmodule started successfully.", mod.Name())
		wg.Add(1)
		runMods++
	}

	if runMods > 0 {
		logger.Printf("start %d modules", runMods)
		<-stopper
	} else {
		logger.Println("No runnable modules, Exit(1)")
		os.Exit(1)
	}
	cancelFun()
	for _, mod := range runModules {
		err := mod.Close()
		wg.Done()
		if err != nil {
			logger.Fatalf("%s\tmodule close failed. error:%+v", mod.Name(), err)
		}
	}
	wg.Wait()
	logger.Println("lost_sample")
	os.Exit(0)

}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
