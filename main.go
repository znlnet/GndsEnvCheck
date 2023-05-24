////go:generate goversioninfo -icon=main1.ico -manifest=main.exe.manifest

package main

import (
	"bufio"
	"fmt"
	"github.com/Starainrt/stario"
	"github.com/druidcaesa/gotool"
	"github.com/go-ping/ping"
	"github.com/google/gopacket/pcap"
	"github.com/gookit/color"

	//mynet "net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/v3/mem"
)

type LSysInfo struct {
	MemAll         uint64
	MemFree        uint64
	MemUsed        uint64
	MemUsedPercent float64
	Days           int64
	Hours          int64
	Minutes        int64
	Seconds        int64

	CpuUsedPercent float64
	OS             string
	Arch           string
	CpuCores       int
}

var filename = ""

func main() {

	apath, _ := os.Getwd()
	filename = apath + "\\gnds-checklog-" + time.Now().Format("2006-1-2_15_04_05") + ".txt"
	runExe()
	myPrintln("Test logfile save in : " + filename)
	infoTest()
	if err := stario.StopUntil("Press any key to end the test", "", false); err != nil {
		myPrintln("Bye bye...")
	}
}

// 判断所给路径文件/文件夹是否存在
func isDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return s.IsDir()
}

func runExe() {
	if !isDir("./gnds.exe") {
		cmd := exec.Command("cmd.exe", "/c", "gnds.exe")
		if runtime.GOOS == "windows" {
			//cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			//Start执行不会等待命令完成，Run会阻塞等待命令完成。
			//err := cmd.Start()
			//err := cmd.Run()
			buf, err := cmd.Output()

			if err != nil {
				//myPrintln("ERROR:", err)
			} else {
				fmt.Println(string(buf))
			}
		}
	}
}

func writeLog(str string, filename string) {
	wronly, err := gotool.FileUtils.OpenFileAppend(filename)
	if err != nil {
		myPrintln("ERROR:", err)
	}
	defer wronly.Close()
	write := bufio.NewWriter(wronly)
	write.WriteString(str)
	//Flush将缓存的文件真正写入到文件中
	write.Flush()
}

func myPrintf(format string, a ...any) (n int, err error) {
	str := fmt.Sprintf(format, a...)
	writeLog(str, filename)
	return fmt.Fprintf(os.Stdout, format, a...)
}
func myPrintln(a ...any) (n int, err error) {
	str := fmt.Sprintln(a)
	writeLog(str, filename)
	return fmt.Println(a)
}
func myErrPrintln(a ...any) {
	str := fmt.Sprintln(a)
	writeLog(str, filename)
	color.Red.Println(a)
}
func myErrorPrintln(a ...any) {
	str := fmt.Sprintln(a)
	writeLog(str, filename)
	color.Error.Println(a)
}
func mySuccessPrintln(a ...any) {
	str := fmt.Sprintln(a)
	writeLog(str, filename)
	color.Success.Println(a)
}

func pingHost(hostname string, count int) bool {
	pinger, err := ping.NewPinger(hostname)
	if err != nil {
		myPrintln("ERROR:", err)
		return true
	}
	if runtime.GOOS == "windows" {
		pinger.SetPrivileged(true)
	}

	pinger.Count = count
	myPrintf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
	myPrintln("Please wating...")

	pinger.OnRecv = func(pkt *ping.Packet) {
		myPrintf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.Ttl)
	}
	pinger.OnDuplicateRecv = func(pkt *ping.Packet) {
		myPrintf("%d bytes from %s: icmp_seq=%d time=%v ttl=%v (DUP!)\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.Ttl)
	}
	pinger.OnFinish = func(stats *ping.Statistics) {
		myPrintf("\n--- %s ping statistics ---\n", stats.Addr)
		myPrintf("%d packets transmitted, %d packets received, %d duplicates, %v%% packet loss\n",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketsRecvDuplicates, stats.PacketLoss)
		myPrintf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
	}

	err = pinger.Run() // Blocks until finished.
	if err != nil {
		myPrintln("Failed to ping target host:", err)
		return true
	}
	stats := pinger.Statistics() // get send/receive/duplicate/rtt stats
	return stats.PacketLoss > 0
}

func GetSysInfo() (info LSysInfo) {
	unit := uint64(1024 * 1024) // MB

	v, _ := mem.VirtualMemory()

	info.MemAll = v.Total
	info.MemFree = v.Free
	info.MemUsed = info.MemAll - info.MemFree
	// 注：使用SwapMemory或VirtualMemory，在不同系统中使用率不一样，因此直接计算一次
	info.MemUsedPercent = float64(info.MemUsed) / float64(info.MemAll) * 100.0 // v.UsedPercent
	info.MemAll /= unit
	info.MemUsed /= unit
	info.MemFree /= unit

	info.OS = runtime.GOOS
	info.Arch = runtime.GOARCH
	info.CpuCores = runtime.GOMAXPROCS(0)

	// 获取200ms内的CPU信息，太短不准确，也可以获几秒内的，但这样会有延时，因为要等待
	cc, _ := cpu.Percent(time.Millisecond*200, false)
	info.CpuUsedPercent = cc[0]

	// 获取开机时间
	boottime, _ := host.BootTime()
	ntime := time.Now().Unix()
	btime := time.Unix(int64(boottime), 0).Unix()
	deltatime := ntime - btime

	info.Seconds = int64(deltatime)
	info.Minutes = info.Seconds / 60
	info.Seconds -= info.Minutes * 60
	info.Hours = info.Minutes / 60
	info.Minutes -= info.Hours * 60
	info.Days = info.Hours / 24
	info.Hours -= info.Days * 24

	myPrintf("info: %#v\n", info)

	infoTest()
	os.Exit(0)
	return
}

var diskTotal uint64 = 0
var diskFree uint64 = 0

func diskList() {
	ddd, _ := disk.Partitions(true)
	for _, s := range ddd {
		if s.Fstype == "NTFS" {
			myd, _ := disk.Usage(s.Mountpoint)
			diskTotal = diskTotal + myd.Total
			diskFree += myd.Free
			myPrintf("Partition %s Total space: %v GB, Free space: %v GB, Usage: %f%%\n", s.Device, myd.Total/1024/1024/1024, myd.Free/1024/1024/1024, myd.UsedPercent)
		}
	}
	myPrintf("HD Total: %v GB ,HD Free: %v GB, HD Usage: %v GB\n", diskTotal/1024/1024/1024, diskFree/1024/1024/1024, (diskTotal-diskFree)/1024/1024/1024)
}

func ipList() {
	addrs, err := net.Interfaces()
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, address := range addrs {
		// 检查ip地址判断是否回环地址
		if address.HardwareAddr != "" && address.Flags != nil && len(address.Addrs) > 0 {
			myPrintf("Netinterface %s :%s\n", address.Name, address.Addrs)
		}
	}
}

func pcapCheck() bool {
	// 得到所有的(网络)设备
	_, err := pcap.FindAllDevs()
	if err != nil {
		myPrintf("Pcap not install :%s\n", err)
		return true
	}
	return false
}

func infoTest() {
	myPrintln("========================Hardware Information=========================")
	c, _ := cpu.Info()
	cc, _ := cpu.Percent(time.Second, false) // 1秒
	//d, _ := disk.Usage("/")
	n, _ := host.Info()
	nv, _ := net.IOCounters(true)
	physicalCnt, _ := cpu.Counts(false)
	logicalCnt, _ := cpu.Counts(true)
	if len(c) > 1 {
		for _, sub_cpu := range c {
			modelname := sub_cpu.ModelName
			cores := sub_cpu.Cores
			myPrintf("CPUs: %v   %v cores \n", modelname, cores)
		}
	} else {
		sub_cpu := c[0]
		modelname := sub_cpu.ModelName
		cores := sub_cpu.Cores
		myPrintf("CPU: %v   %v cores \n", modelname, cores)
	}

	//unit := uint64(1024 * 1024 *1024) // MB

	v, _ := mem.VirtualMemory()

	myPrintf("CPU Physical count: %d \nCPU Logical count: %d\n", physicalCnt, logicalCnt)
	myPrintf("CPU Used: used %f%%\n", cc[0])
	diskList()
	//myPrintf("HD: %v GB Free: %v GB Usage:%f%%\n", d.Total/1024/1024/1024, d.Free/1024/1024/1024, d.UsedPercent)
	myPrintf("OS: %v(%v) %v\n", n.Platform, n.PlatformFamily, n.PlatformVersion)
	myPrintf("Hostname: %v\n", n.Hostname)
	myPrintf("Memory: %v MB\n", v.Total/1024/1024)
	ipList()
	myPrintf("Network: %v bytes / %v bytes\n", nv[0].BytesRecv, nv[0].BytesSent)
	myPrintln("=====================================================================")
	myPrintf("\n")

	flag := true

	//API网关判断
	lostGeekyApiPing := pingHost("gnds-api-cn.geely.com", 10)
	//gnds-cdn
	lostgndsCdn := pingHost("gnds-cdn.geely.com", 5)
	//OTA
	lostotaCdn := pingHost("otasea-cdn.geely.com", 5)

	//互联网判断
	lostNetPing := pingHost("www.qq.com", 5)
	myPrintf("\n")
	myPrintln("========================Non-conforming Items=========================")
	if lostGeekyApiPing {
		flag = false
		myErrPrintln("[NetWork]--->Your network cannot connect to the gnds-api-cn.geely.com")
	}

	if lostgndsCdn {
		flag = false
		myErrPrintln("[NetWork]--->Your network cannot connect to the gnds-cdn.geely.com")
	}

	if lostotaCdn {
		flag = false
		myErrPrintln("[NetWork]--->Your network cannot connect to the otasea-cdn.geely.com")
	}

	if lostNetPing {
		flag = false
		myErrPrintln("[NetWork]--->Your network cannot connect to the Internet")
	}

	//操作系统判断
	if !(strings.Contains(n.Platform, "Windows 10") || strings.Contains(n.Platform, "Windows 11")) {
		flag = false
		myErrPrintln("[OS]--->Your operating system is not Windows 10 or Windows 11")
	}

	//CPU判断
	if physicalCnt < 2 || logicalCnt < 4 {
		flag = false
		myErrPrintln("[CPU]--->The CPU has at least 2 physical cores and at least 4 logical cores")
	}

	//内存判断
	if v.Total/1024/1024 < 8192 {
		flag = false
		myErrPrintln("[Memory]--->Total system memory at least 8GB")
	}

	//可用硬盘空间判断
	if diskFree/1024/1024/1024 < 40 {
		flag = false
		myErrPrintln("[Disk]--->The disk has less than 40GB of free space")
	}

	//总硬盘空间判断
	if diskTotal/1024/1024/1024 < 400 {
		flag = false
		myErrPrintln("[Disk]--->The disk has less than 400GB of total space")
	}

	if pcapCheck() {
		flag = false
		myErrPrintln("[PCAP]--->Pcap drive not load, please reinstall win10pcap")
	}

	//Pcap文件判断
	if runtime.GOOS == "windows" && isDir("c:\\Windows\\System32\\packet.dll") {
		flag = false
		myErrPrintln("[PCAP]--->Pcap not install, please install win10pcap")
	}
	myPrintln("=====================================================================")
	myPrintf("\n")
	myPrintln("======================Test Result==========================")
	if flag {
		mySuccessPrintln("Success!!! This computer can be installed the GNDS client normally!")
	} else {
		myErrorPrintln("Fail!!! This computer cannot be properly used for the GNDS client!")
	}
	myPrintln("===========================================================")

}
