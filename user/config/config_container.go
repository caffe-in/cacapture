package config

type ContainerConfig struct {
	eConfig
	PcapFile string `json:"pcapFile"` // pcapFile  the  raw  packets  to file rather than parsing and printing them out.
	Ifname   string `json:"ifName"`   // (TC Classifier) Interface name on which the probe will be attached.

}
