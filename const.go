package main

const (
	ProbeTypeUprobe = "uprobe"
	ProbeTypeKprobe = "kprobe"
	ProbeTypeTC     = "TC"
	ProbeTypeTP     = "tracepoint"
	ProbeTypeXDP    = "XDP"
)
const (
	ModuleNameBash     = "EBPFProbeBash"
	ModuleNameMysqld   = "EBPFProbeMysqld"
	ModuleNamePostgres = "EBPFProbePostgres"
	ModuleNameOpenssl  = "EBPFProbeOPENSSL"
	ModuleNameGnutls   = "EBPFProbeGNUTLS"
	ModuleNameNspr     = "EBPFProbeNSPR"
	ModuleNameGotls    = "EBPFProbeGoTLS"
)
