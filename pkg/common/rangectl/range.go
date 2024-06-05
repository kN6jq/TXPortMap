package rangectl

import (
	"bufio"
	"errors"
	"fmt"
	ps "github.com/4dogs-cn/TXPortMap/pkg/common/ipparser"
	"os"
	"strconv"
	"strings"
)

type Range struct {
	Begin uint64
	End   uint64
}

/*
*

	RemoveExcFromTaskIps 从任务范围内移除需要排除的Ip或端口
	返回值：
	1. 表示任务列表范围，返回值2有效时才有意义
	2. 表示返回值是否有效，只有排除范围把任务列表分成两段时才有效
*/
func (r *Range) RemoveExcFromTaskIps(exclude Range) (Range, bool) {
	var split Range
	var tmp = *r

	if r.Begin > exclude.End || r.End < exclude.Begin {
		return Range{}, false
	}

	if r.Begin >= exclude.Begin && r.End <= exclude.End {
		*r = Range{}
		return Range{}, false
	}

	if r.Begin >= exclude.Begin && r.End > exclude.End {
		r.Begin = exclude.End + 1
		return Range{}, false
	}

	if r.Begin < exclude.Begin && r.End <= exclude.End {
		r.End = exclude.Begin - 1
		return Range{}, false
	}

	if r.Begin < exclude.Begin && r.End > exclude.End {
		r.End = exclude.Begin - 1
		split.Begin = exclude.End + 1
		split.End = tmp.End

		return split, true
	}

	return Range{}, false
}

// ParsePortRange 解析自定义端口范围
func ParsePortRange(port string) (Range, error) {
	var result Range
	port = strings.TrimSpace(port)
	// 解析-
	if strings.Contains(port, "-") {
		prange := strings.Split(port, "-")
		start := prange[0]
		stop := prange[1]

		begin, err := strconv.Atoi(start)
		if err != nil {
			return Range{}, err
		}

		end, err := strconv.Atoi(stop)
		if err != nil {
			return Range{}, err
		}

		result.Begin = uint64(begin)
		result.End = uint64(end)
	} else {
		// 单个端口
		num, err := strconv.Atoi(port)
		if err != nil {
			return Range{}, err
		}

		result.Begin = uint64(num)
		result.End = uint64(num)
	}

	if result.Begin > result.End || result.Begin > 65536 || result.End > 65535 {
		return Range{}, errors.New("port range failed")
	}

	return result, nil
}

// ParseIpv4Range 解析Ip地址范围，
func ParseIpv4Range(ip string) (Range, error) {
	var result Range

	// 解析cidr段
	index := strings.Index(ip, "/")
	if index != -1 {
		ips, err := ps.CidrParse(ip)
		if err != nil {
			fmt.Println(err)
			return Range{}, err
		}

		begin, err := ps.ParseIPv4(ips[0])
		if err != nil {
			fmt.Println(err)
			return Range{}, err
		}

		result.Begin = begin

		end, err := ps.ParseIPv4(ips[len(ips)-1])
		if err != nil {
			fmt.Println(err)
			return Range{}, err
		}

		result.End = end

		return result, nil

	}

	// 解析-
	index = strings.Index(ip, "-")
	if index != -1 {
		ips := strings.Split(ip, "-")

		isIP := ps.IsIP(ips[1])
		if !isIP {
			//return Range{}, err
			// 假设ips[1]是ip的一个主机位,那么生成ips[0]得最后主机位到ips[1]
			// 将ips[1]转为int
			ipend, _ := strconv.Atoi(ips[1])
			ipbeg, _ := strconv.Atoi(strings.Split(ips[0], ".")[3])
			if ipend <= 255 && ipbeg < ipend {
				step := ipend - ipbeg
				for i := 0; i <= step; i++ {
					ip := strings.Split(ips[0], ".")
					ip[3] = strconv.Itoa(ipbeg + i)
					ipstr := strings.Join(ip, ".")
					ipnum, _ := ps.ParseIPv4(ipstr)
					if i == 0 {
						result.Begin = ipnum
					}
					if i == step {
						result.End = ipnum
					}
				}

			} else {
				return Range{}, errors.New("ip range failed")
			}
		} else {
			begin, err := ps.ParseIPv4(ips[0])
			if err != nil {
				return Range{}, err
			}

			result.Begin = begin

			// 假设ips[1]是一个ip
			end, err := ps.ParseIPv4(ips[1])
			if err != nil {
				return Range{}, err
			}
			result.End = end

			if end < begin {
				return Range{}, errors.New("End ip is large than start ip")
			}

			return result, nil
		}
		return result, nil

	}

	// 说明是单个的ip
	num, err := ps.ParseIPv4(ip)
	if err != nil {
		return Range{}, err
	}

	result.Begin = num
	result.End = num

	return result, nil
}

// ParseIPFromFile 从文件中解析IP地址及域名
func ParseIPFromFile(path string) ([]Range, error) {
	var ips []Range
	p, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if p.IsDir() {
		return nil, fmt.Errorf("could not input a dir: %s", path)
	}

	input, err := os.Open(path)

	if err != nil {
		return nil, fmt.Errorf("open file error: %s", path)
	}

	scanner := bufio.NewScanner(input)

	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip == "" {
			continue
		}
		if ps.IsIP(ip) || ps.IsIPRange(ip) || ps.IsIPRangeDash(ip) {
			rst, err := ParseIpv4Range(ip)
			if err != nil {
				continue
			}
			ips = append(ips, rst)
		} else {
			tmp_ips, mask, err := ps.DomainToIp(ip)
			if err != nil {
				fmt.Println(err)
				continue
			}
			for _, ip := range tmp_ips {
				addr := ip
				if mask != "" {
					addr = ip + "/" + mask
				}
				result, err := ParseIpv4Range(addr)

				if err != nil {
					fmt.Println("Error occured while parse iprange")
					continue
				}
				ips = append(ips, result)
			}
		}
	}
	return ips, nil
}
