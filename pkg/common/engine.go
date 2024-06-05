package common

import (
	"fmt"
	"github.com/4dogs-cn/TXPortMap/pkg/Ginfo/Ghttp"
	"github.com/4dogs-cn/TXPortMap/pkg/Ginfo/Gnbtscan"
	ps "github.com/4dogs-cn/TXPortMap/pkg/common/ipparser"
	rc "github.com/4dogs-cn/TXPortMap/pkg/common/rangectl"
	"github.com/4dogs-cn/TXPortMap/pkg/conversion"
	"github.com/4dogs-cn/TXPortMap/pkg/output"
	"go.uber.org/ratelimit"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Addr struct {
	ip   string
	port uint64
}

type NBTScanIPMap struct {
	sync.Mutex
	IPS map[string]struct{}
}

// type Range struct {
// 	Begin uint64
// 	End   uint64
// }

var Web []string

var (
	Writer     output.Writer
	NBTScanIPs = NBTScanIPMap{IPS: make(map[string]struct{})}
)

type Engine struct {
	TaskIps     []rc.Range // 待扫描的ip
	TaskPorts   []rc.Range // 待扫描的端口
	ExcdPorts   []rc.Range // 待排除端口
	ExcdIps     []rc.Range // 待排除的Ip
	RandomFlag  bool       // 是否随机扫描
	WorkerCount int        // 扫描线程数
	TaskChan    chan Addr  // 传递待扫描的ip端口对
	//DoneChan chan struct{}  // 任务完成通知
	Wg *sync.WaitGroup
}

// SetIP as seen
func (r *NBTScanIPMap) SetIP(ip string) {
	r.Lock()
	defer r.Unlock()

	r.IPS[ip] = struct{}{}
}

// HasIP checks if an ip has been seen
func (r *NBTScanIPMap) HasIP(ip string) bool {
	r.Lock()
	defer r.Unlock()

	_, ok := r.IPS[ip]
	return ok
}

// 扫描目标建立，ip:port发送到任务通道
func (e *Engine) Run() {
	var addr Addr
	e.Wg.Add(e.WorkerCount) // 添加workerCount个任务
	go e.Scheduler()        // 调度器

	// fmt.Println(e.TaskPorts)
	// 先使用checkConnection判断是否为cdn ip

	// TODO:: if !e.RandomFlag
	// TODO:: 假随机扫描
	if !e.RandomFlag {
		// 随机扫描，向任务通道随机发送addr
		e.randomScan()

	} else {
		// 顺序扫描，向任务通道顺序发送addr
		for _, ipnum := range e.TaskIps {
			for ips := ipnum.Begin; ips <= ipnum.End; ips++ {
				ip := ps.UnParseIPv4(ips)

				for _, ports := range e.TaskPorts {
					for port := ports.Begin; port <= ports.End; port++ {
						addr.ip = ip
						addr.port = port

						//e.SubmitTask(addr)
						//fmt.Println("ip:",ip,":port",port)
						e.TaskChan <- addr
					}
				}
			}
		}
	}

	// 扫描任务发送完成，关闭通道
	//fmt.Println("Task Add done")
	close(e.TaskChan)
}

func (e *Engine) SubmitTask(addr Addr) {
	//fmt.Printf("submit# %s:%d\n", addr.ip, addr.port)
	go func() {
		e.TaskChan <- addr
	}()
}

// 扫描任务创建
func (e *Engine) Scheduler() {
	for i := 0; i < e.WorkerCount; i++ {
		worker(e.TaskChan, e.Wg)
	}
}

// 参数解析，对命令行中传递的参数进行格式化存储
func (e *Engine) Parser() error {
	var err error
	// 创建格式化输出 接受参数 是否禁用颜色, 是否输出json格式, 输出文件, 输出trace文件
	Writer, err = output.NewStandardWriter(nocolor, json, rstfile, tracelog)
	if err != nil {
		return err
	}
	var ports []string
	// TODO:: 待增加排除ip和排除端口流程

	// 循环待扫描ip,判断是否为ip或域名,并解析为result添加进e.TaskIps
	for _, ipstr := range cmdIps {
		if ps.IsIP(ipstr) || ps.IsIPRange(ipstr) || ps.IsIPRangeDash(ipstr) {
			result, err := rc.ParseIpv4Range(ipstr)
			if err != nil {
				return err
			}

			e.TaskIps = append(e.TaskIps, result)
		} else {
			// 说明是域名，需要对域名进行解析
			ips, mask, err := ps.DomainToIp(ipstr)
			if err != nil {
				fmt.Println(err)
				return err
			}
			for _, ip := range ips {
				addr := ip
				if mask != "" {
					addr = ip + "/" + mask
				}

				result, err := rc.ParseIpv4Range(addr)

				if err != nil {
					fmt.Println("Error occured while parse iprange")
					return err
				}

				e.TaskIps = append(e.TaskIps, result)
			}
		}
	}

	// 如果存在ip文件，则解析ip文件
	if ipFile != "" {
		rst, err := rc.ParseIPFromFile(ipFile)
		if err == nil {
			for _, r := range rst {
				e.TaskIps = append(e.TaskIps, r)
			}
		}
	}

	// 设置排除ip
	if len(excIps) != 0 {
		for _, ipstr := range excIps {
			if ps.IsIP(ipstr) || ps.IsIPRange(ipstr) {
				result, err := rc.ParseIpv4Range(ipstr)
				if err != nil {
					fmt.Println("Error occured while parse iprange")
					return err
				}

				e.ExcdIps = append(e.ExcdIps, result)
			} else {
				// 说明是域名，需要对域名进行解析
				ips, mask, err := ps.DomainToIp(ipstr)
				if err != nil {
					fmt.Println(err)
					return err
				}
				for _, ip := range ips {
					addr := ip
					if mask != "" {
						addr = ip + "/" + mask
					}

					result, err := rc.ParseIpv4Range(addr)

					if err != nil {
						fmt.Println("Error occured while parse iprange")
						return err
					}

					e.ExcdIps = append(e.ExcdIps, result)
				}
			}
		}

		// 排除ip的核心方法
		for _, ipe := range e.ExcdIps {
			for i := 0; i < len(e.TaskIps); i++ {
				if res, ok := (e.TaskIps[i]).RemoveExcFromTaskIps(ipe); ok {
					e.TaskIps = append(e.TaskIps, res)
				}
			}
		}
	}

	// 说明有自定义端口
	if len(cmdPorts) != 0 {
		ports = cmdPorts
	} else {
		if !cmdT1000 {
			// Top100端口扫描
			ports = Top100Ports

		} else {
			// Top1000端口扫描
			ports = Top1000Ports
		}
	}

	// 解析命令行端口范围
	for _, portstr := range ports {
		result, err := rc.ParsePortRange(portstr)
		if err != nil {
			fmt.Println(err)
			return err
		}

		e.TaskPorts = append(e.TaskPorts, result)
	}

	// 解析待排除端口范围
	if len(excPorts) != 0 {
		for _, portstr := range excPorts {
			result, err := rc.ParsePortRange(portstr)
			if err != nil {
				fmt.Println(err)
				return err
			}

			e.ExcdPorts = append(e.ExcdPorts, result)
		}

		// range出来的其实是原始值的拷贝，因此，这里需要对原始值进行修改时，不能使用range
		for _, exp := range e.ExcdPorts {
			for i := 0; i < len(e.TaskPorts); i++ {
				if res, ok := (e.TaskPorts[i]).RemoveExcFromTaskIps(exp); ok {
					e.TaskPorts = append(e.TaskPorts, res)
				}
			}
		}
	}

	// fmt.Println(e.TaskPorts)
	// fmt.Println(e.ExcdPorts)

	return nil
}

// 创建引擎
func CreateEngine() *Engine {

	// 创建限速器
	if limit > 1 {
		Limiter = ratelimit.New(limit)
	} else {
		Limiter = ratelimit.NewUnlimited()
	}

	// 返回一个创建好的引擎结构体
	return &Engine{
		RandomFlag:  cmdRandom,
		TaskChan:    make(chan Addr, 1000), // 创建带有1000个缓冲的通道
		WorkerCount: NumThreads,            // 设置线程数
		Wg:          &sync.WaitGroup{},     // 创建一个WaitGroup
	}
}

// nbtscaner
func nbtscaner(ip string) {
	resultEvent := output.ResultEvent{Target: ip, Info: &output.Info{}}
	nbInfo, err := Gnbtscan.Scan(ip)
	if err == nil && len(nbInfo) > 0 {
		resultEvent.Info.Service = "nbstat"
		resultEvent.Info.Banner = nbInfo
		Writer.Write(&resultEvent)
	}
}

func scanner(ip string, port uint64) {
	//fmt.Printf("Scanning %s:%d\n", ip, port)
	var dwSvc int                       // dwSvc是返回的端口号
	var iRule = -1                      // iRule是规则编号
	var bIsIdentification = false       // bIsIdentification是标识符
	var resultEvent *output.ResultEvent // 识别结果保存的
	var packet []byte                   // 报文
	//var iCntTimeOut = 0

	// 优先识别协议端口
	// 端口开放状态，发送报文，获取响应
	// 先判断端口是不是优先识别协议端口
	// todo: 自定义开启优先识别端口
	for _, svc := range St_Identification_Port {
		// 判断端口是否是优先识别协议端口
		if port == svc.Port {
			bIsIdentification = true                       // 设置标识
			iRule = svc.Identification_RuleId              // 设置规则编号
			data := st_Identification_Packet[iRule].Packet // 根据规则编号获取报文
			// 发送报文
			dwSvc, resultEvent = SendIdentificationPacketFunction(data, ip, port)
			break
		}
	}
	if (dwSvc > UNKNOWN_PORT && dwSvc <= SOCKET_CONNECT_FAILED) || dwSvc == SOCKET_READ_TIMEOUT {
		Writer.Write(resultEvent)
		return
	}

	// 识别其他协议
	// 发送其他协议查询包
	// 每个端口都会发送IdentificationProtocol的指纹报文识别
	for i := 0; i < iPacketMask; i++ {
		// 超时2次,不再识别
		if bIsIdentification && iRule == i {
			continue
		}
		if i == 0 {
			// 说明是http，数据需要拼装一下
			var szOption string
			if port == 80 {
				szOption = fmt.Sprintf("%s%s\r\n\r\n", st_Identification_Packet[0].Packet, ip)
			} else {
				//fmt.Println("start")
				szOption = fmt.Sprintf("%s%s:%d\r\n\r\n", st_Identification_Packet[0].Packet, ip, port)
			}
			packet = []byte(szOption)
		} else {
			packet = st_Identification_Packet[i].Packet
		}
		//packet, _ = hex.DecodeString("73746174730d0a717569740d0a")
		dwSvc, resultEvent = SendIdentificationPacketFunction(packet, ip, port)

		if i == 0 {

		}

		if (dwSvc > UNKNOWN_PORT && dwSvc <= SOCKET_CONNECT_FAILED) || dwSvc == SOCKET_READ_TIMEOUT {
			Writer.Write(resultEvent)
			return
		}
	}
	// 没有识别到服务，也要输出当前开放端口状态
	//fmt.Println("start")
	//Writer.Write(resultEvent)
	//fmt.Println("end")
}

// 创建工作线程
func worker(res chan Addr, wg *sync.WaitGroup) {
	go func() {
		defer wg.Done()

		for addr := range res {
			//使用nbtscan进行扫描,如果开启并且当前ip没有被扫描过
			if nbtscan && NBTScanIPs.HasIP(addr.ip) == false {
				NBTScanIPs.SetIP(addr.ip)
				nbtscaner(addr.ip)
			}
			Limiter.Take()              // 限速
			scanner(addr.ip, addr.port) // 扫描端口
		}

	}()
}

// 发送识别报文
func SendIdentificationPacketFunction(data []byte, ip string, port uint64) (int, *output.ResultEvent) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	// 创建一个ResultEvent结构体,用来输出结果
	even := &output.ResultEvent{
		Target: addr,
		Info:   &output.Info{},
	}

	//fmt.Println(addr)
	// 创建一个conn连接
	var dwSvc int = UNKNOWN_PORT
	conn, err := net.DialTimeout("tcp", addr, time.Duration(tout*1000)*time.Millisecond)
	if err != nil {
		// 端口是closed状态
		Writer.Request(ip, conversion.ToString(port), "tcp", fmt.Errorf("time out"))
		return SOCKET_CONNECT_FAILED, nil
	}

	defer conn.Close()

	// Write方法是非阻塞的
	// 如果发送发送失败，那么端口是closed状态
	if _, err := conn.Write(data); err != nil {
		// 端口是开放的
		Writer.Request(ip, conversion.ToString(port), "tcp", err)
		return dwSvc, even
	}

	// 直接开辟好空间，避免底层数组频繁申请内存
	var fingerprint = make([]byte, 0, 65535)
	var tmp = make([]byte, 256)
	// 存储读取的字节数
	var num int
	var szBan string
	var szSvcName string

	// 这里设置成6秒是因为超时的时候会重新尝试5次，

	readTimeout := 6 * time.Second

	// 设置读取的超时时间为6s
	conn.SetReadDeadline(time.Now().Add(readTimeout))

	for {
		// Read是阻塞的
		n, err := conn.Read(tmp)
		if err != nil {
			// 虽然数据读取错误，但是端口仍然是open的
			// fmt.Println(err)
			if err != io.EOF {
				dwSvc = SOCKET_READ_TIMEOUT
				// fmt.Printf("Discovered open port\t%d\ton\t%s\n", port, ip)
			}
			break
		}

		if n > 0 {
			// 读取到的数据追加到fingerprint中
			num += n
			fingerprint = append(fingerprint, tmp[:n]...)
		} else {
			// 虽然没有读取到数据，但是端口仍然是open的
			// fmt.Printf("Discovered open port\t%d\ton\t%s\n", port, ip)
			break
		}
	}
	Writer.Request(ip, conversion.ToString(port), "tcp", err)
	//fmt.Println(num)
	//fmt.Println(fingerprint)
	// 如果没有读取到数据，并且端口是open状态,那么直接返回,这里考虑waf
	//if num == 0 && len(fingerprint) == 0 {
	//	return dwSvc, nil
	//}

	// 服务识别
	if num > 0 {
		dwSvc = ComparePackets(fingerprint, num, &szBan, &szSvcName)
		//if len(szBan) > 15 {
		//	szBan = szBan[:15]
		//}
		// dwSvc是返回的端口号
		if dwSvc > UNKNOWN_PORT && dwSvc < SOCKET_CONNECT_FAILED {
			//even.WorkingEvent = "found"
			// 如果是http或者https，获取http标题
			if szSvcName == "ssl/tls" || szSvcName == "http" {
				var rst Ghttp.Result
				rst = Ghttp.GetHttpTitle(ip, Ghttp.HTTP, int(port))

				if rst.StatusCode == 400 {
					rst = Ghttp.GetHttpTitle(ip, Ghttp.HTTPS, int(port))
					szSvcName = "https"
				} else {
					szSvcName = "http"
				}
				// 如果标题中包含waf，那么直接返回
				for _, waf := range Waf_Title {
					if strings.Contains(rst.Title, waf) {
						return dwSvc, nil
					}
				}
				// 如果webserver中包含waf，那么直接返回
				for _, webserver := range Waf_WebServer {
					if strings.Contains(rst.WebServer, webserver) {
						return dwSvc, nil
					}
				}
				webhttp := fmt.Sprintf("%s://%s:%d", szSvcName, ip, port)
				Web = append(Web, webhttp)
				// even.WorkingEvent就是http识别的结果
				even.WorkingEvent = rst
				cert, err0 := Ghttp.GetCert(ip, int(port))
				if err0 != nil {
					cert = ""
				}
				// even.Info.Cert 就是证书识别的结果
				even.Info.Cert = cert
				//fmt.Println(rst.Title)
				//if strings.Contains(rst.Title,"HTTPS port") && rst.StatusCode == 400 {
				//	szSvcName = "ssl/tls"
				//}else {
				//	szSvcName = "http"
				//}

			} else {
				// szBan其实就是返回的字节切片
				// 如果没有识别到服务,并且不是http或者https，就是返回的字节切片
				even.Info.Banner = strings.TrimSpace(szBan)
			}
			// szSvcName其实就是服务名
			even.Info.Service = szSvcName
			even.Time = time.Now()
			// fmt.Printf("Discovered open port\t%d\ton\t%s\t\t%s\t\t%s\n", port, ip, szSvcName, strings.TrimSpace(szBan))
			//Writer.Write(even)
			//return dwSvc, even
		}
	}

	return dwSvc, even
}

// randomScan 随机扫描, 有问题，扫描C段时扫描不到，
// TODO::尝试遍历ip，端口顺序打乱扫描
func (e *Engine) randomScan() {
	// 投机取巧，打乱端口顺序，遍历ip扫描
	var portlist = make(map[int]uint64)
	var index int
	var addr Addr

	// 遍历端口
	for _, ports := range e.TaskPorts {
		for port := ports.Begin; port <= ports.End; port++ {
			portlist[index] = port
			index++
		}
	}

	if Cdn {
		for _, ipnum := range e.TaskIps {
			for ips := ipnum.Begin; ips <= ipnum.End; ips++ {
				ip := ps.UnParseIPv4(ips)
				isCdn := checkConnection(ip)
				if isCdn {
					fmt.Println("cdnIp: " + ip)

				} else {
					for _, po := range portlist {
						addr.ip = ip
						addr.port = po

						e.TaskChan <- addr
					}
				}
			}
		}
	} else {
		for _, ipnum := range e.TaskIps {
			for ips := ipnum.Begin; ips <= ipnum.End; ips++ {
				ip := ps.UnParseIPv4(ips)
				for _, po := range portlist {
					addr.ip = ip
					addr.port = po
					e.TaskChan <- addr
				}
			}
		}
	}

}

// 统计待扫描的ip数目
func (e *Engine) ipRangeCount() uint64 {
	var count uint64
	for _, ipnum := range e.TaskIps {
		count += ipnum.End - ipnum.Begin + 1
	}

	return count
}

// 统计待扫描的端口数目
func (e *Engine) portRangeCount() uint64 {
	var count uint64
	for _, ports := range e.TaskPorts {
		count += ports.End - ports.Begin + 1
	}

	return count
}

func checkConnection(host string) bool {
	var ports []int
	var verify int
	for i := 0; i < 3; i++ {
		// 随机生成端口
		port := randInt(1024, 65535)
		ports = append(ports, port)
		connection := checkTCPConnection(host, port)
		if connection {
			verify++
		}
	}
	if verify >= 2 {
		return true
	} else {
		return false
	}

}

func checkTCPConnection(host string, port int) bool {

	addr := host + ":" + strconv.Itoa(port)
	//conn, err := net.Dial("tcp", host+":"+strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, time.Duration(tout*1000)*time.Millisecond)

	if err != nil {
		return false
	}
	defer conn.Close()

	// 等待服务器响应，超时时间为1秒
	if err := conn.SetDeadline(time.Now().Add(time.Duration(tout*1000) * time.Millisecond)); err != nil {
		return false
	}

	return true
}

func randInt(min int, max int) int {
	// 种子时间用于初始化随机数生成器
	rand.Seed(time.Now().UnixNano())

	// 如果max小于min，会返回一个错误，所以需要确保max大于min
	if max < min {
		max, min = min, max
	}

	// 生成一个在[0, max-min)范围内的随机整数，然后加上min得到[min, max]范围内的整数
	return rand.Intn(max-min) + min
}
