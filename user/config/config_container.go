package config

type ContainerConfig struct {
	eConfig
	//Curlpath   string `json:"curlPath"` //curl的文件路径
	Openssl    string `json:"openssl"`
	Pthread    string `json:"pThread"`    // /lib/x86_64-linux-gnu/libpthread.so.0
	Model      string `json:"model"`      // eCapture Openssl capture model. text:pcap:keylog
	PcapFile   string `json:"pcapFile"`   // pcapFile  the  raw  packets  to file rather than parsing and printing them out.
	KeylogFile string `json:"keylog"`     // Keylog  The file stores SSL/TLS keys, and eCapture captures these keys during encrypted traffic communication and saves them to the file.
	Ifname     string `json:"ifName"`     // (TC Classifier) Interface name on which the probe will be attached.
	Port       uint16 `json:"port"`       // capture port
	SslVersion string `json:"sslVersion"` // openssl version like 1.1.1a/1.1.1f/boringssl_1.1.1
	CGroupPath string `json:"CGroupPath"` // cgroup path, used for filter process
	ElfType    uint8  //
	IsAndroid  bool   //	is Android OS ?
	AndroidVer string // Android OS version
}

func (oc *ContainerConfig) Check() error {
	return nil
}
