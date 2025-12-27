package shadow

import (
	"bufio"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"strings"
)

// func runCommand(command string) (response string) {
// 	fmt.Printf("! %s\n", command)
// 	output, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
// 	if err != nil {
// 		return fmt.Sprintf("ERROR: %s", err)
// 	}
// 	return string(output)
// }

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

// This is some AI nonsense, but I prompted it to
// find the interface regardless of whether or not
// something like net.Dial(8.8.8.8:80) would work,
// in other words, we dont need to do any connecting
// to make sure that we can get the outward interface
func getOutwardIface() (*net.Interface, error) {
	// Open net route file
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Open scanner
	sc := bufio.NewScanner(f)
	if !sc.Scan() { // header
		return nil, errors.New("empty /proc/net/route")
	}

	// Iterate until we find an interface who owns the default route
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		ifaceName := fields[0]
		dest := fields[1]
		if dest == "00000000" { // default route
			ifc, err := net.InterfaceByName(ifaceName)
			if err != nil {
				return nil, err
			}

			return ifc, nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("no default route found")
}

func getOutboundIP() {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	SrcIP = localAddr.IP
}
