package cmd

import (
	"cacapture/user/config"
	"cacapture/user/module"
	"context"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netns"
)

const (
	defaultPid uint64 = 0
	defaultUid uint64 = 0
)

var rc = &config.ContainerConfig{}

var rootCmd = &cobra.Command{
	Use:   "cacapture",
	Short: "Capture and analyze the container's network traffic",
	Long:  `Capture and analyze the container's network traffic`,
	Run:   cacaptureCommandFunc,
}

func init() {
	log.Println("hello")
	rootCmd.PersistentFlags().BoolVarP(&rc.Debug, "debug", "d", false, "enable debug logging.(coming soon)")
	rootCmd.PersistentFlags().BoolVar(&rc.IsHex, "hex", false, "print byte strings as hex encoded strings")
	rootCmd.PersistentFlags().IntVar(&rc.PerCpuMapSize, "mapsize", 20480, "eBPF map size per CPU,for events buffer. default:1024 * PAGESIZE. (KB)")
	rootCmd.PersistentFlags().Uint64VarP(&rc.Pid, "pid", "p", defaultPid, "if pid is 0 then we target all pids")
	rootCmd.PersistentFlags().Uint64VarP(&rc.Uid, "uid", "u", defaultUid, "if uid is 0 then we target all users")
	rootCmd.PersistentFlags().StringVar(&rc.ContainerID, "containerID", "", "containerID")
	rootCmd.PersistentFlags().StringVar(&rc.Ifname, "ifname", "", "ifname")
	rootCmd.PersistentFlags().StringVar(&rc.PcapFile, "PcapFile", "", "pcapngFilename")
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

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFun := context.WithCancel(context.Background())

	logger := log.New(os.Stdout, "cacapture: ", log.LstdFlags)
	// gConf, err := getGlobalConf(cmd)
	// if err != nil {
	// 	logger.Println("Error:", err)
	// 	return
	// }

	logger.Printf("CACAPTURE:: Pid Info: %d", os.Getpid())

	var modNames = []string{module.ModuleNameContainer}

	var runMods uint8
	var runModules = make(map[string]module.IModule)
	var wg sync.WaitGroup

	nsHandle, err := netns.GetFromDocker(rc.ContainerID)
	if err != nil {
		logger.Printf("Container %s cann't find: %v", rc.ContainerID, err)
		panic(err)
	}
	defer nsHandle.Close()

	err = netns.Set(nsHandle)
	if err != nil {
		logger.Printf("Container %s namespace cann't set: %v", rc.ContainerID, err)
		panic(err)
	}

	for _, modName := range modNames {
		mod := module.GetModuleByName(modName)
		if mod == nil {
			logger.Printf("Module %s not found", modName)
			break
		}

		logger.Printf("%s\tmodule initialization", mod.Name())
		var conf config.IConfig
		conf = rc
		conf.SetPerCpuMapSize(1024)

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
		logger.Printf("ECAPTURE :: \tstart %d modules", runMods)
		<-stopper
	} else {
		logger.Println("ECAPTURE :: \tNo runnable modules, Exit(1)")
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
