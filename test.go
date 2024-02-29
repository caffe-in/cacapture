package main

import (
	"fmt"
	"net"
	"runtime"

	"github.com/vishvananda/netns"
)

func main_test() {
	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save the current network namespace
	origns, _ := netns.Get()
	defer origns.Close()

	// Create a new network namespace
	newns, _ := netns.New()
	defer newns.Close()

	// Do something with the network namespace
	ifaces, _ := net.Interfaces()
	fmt.Printf("Interfaces: %v\n", ifaces)

	// Switch back to the original namespace
	netns.Set(origns)
}
