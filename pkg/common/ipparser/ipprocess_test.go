package ipparser

import (
	"fmt"
	"math/big"
	"net"
	"testing"
)

func Test(t *testing.T) {
	dash := IsIPRangeDash("117.78.24.41-43")
	if dash {
		t.Log("dash")
	} else {
		t.Log("not dash")
	}
}

func ParseIPv41(ipstr string) {

	ip := big.NewInt(0)
	tmp := net.ParseIP(ipstr).To4()
	fmt.Println(tmp)
	if tmp == nil {
		fmt.Println("not ipv4")
	}
	ip.SetBytes(tmp)
	fmt.Println(ip.Uint64())

}

func TestParseIPv4(t *testing.T) {
	ParseIPv41("117.78.24.41")

}
