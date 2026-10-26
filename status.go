package vodafone

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type WAN struct {
	MacAddress  net.HardwareAddr
	Ipv4Address net.IP
	Ipv6Address net.IP
}

type Port struct {
	Name    string
	Enabled bool
	Bitrate uint //Mbps
}

type LAN struct {
	MacAddress  net.HardwareAddr
	Ipv4Address *net.IPNet
	Ipv6Address *net.IPNet
	Ipv4Gateway net.IP
	LANPorts    []Port
}

type WLAN struct {
	Enabled    bool
	SSID       string
	MacAddress net.HardwareAddr
	Channel    uint
	Security   string
	Bandwidth  uint // MHz
}

type Status struct {
	SerialNumber    string
	FirmwareVersion string
	HardwareType    string
	Uptime          time.Duration
	CurrentTime     time.Time

	WanInterface WAN

	LanInterface LAN

	WLAN5G  WLAN
	WLAN24G WLAN
}

var wlanEnable = regexp.MustCompile("js_WLAN(24|5)G_Enable")
var wlanSSID = regexp.MustCompile("js_WLAN(24|5)G_SSID")
var wlanMacAddress = regexp.MustCompile("js_WLAN(24|5)GMACAddress")
var wlanChannel = regexp.MustCompile("js_WLAN(24|5)G_Channel")
var wlanSecurity = regexp.MustCompile("js_WLAN(24|5)G_Security")
var wlanBandwidth = regexp.MustCompile("js_WLAN(24|5)G_BandWidth")

var port = regexp.MustCompile(`js_ethernet_port(\d)_(status|bitrate)`)

func (s *Status) fillStatusStruct(line string) {
	// Get the key value pair of this line
	// It should be looking like this:
	// var KEY = 'VALUE';
	line = strings.TrimSpace(line)
	ok := false
	if line, ok = strings.CutPrefix(line, "var"); !ok {
		return
	}

	key, value, ok := strings.Cut(line, "=")
	if !ok {
		return
	}
	key = strings.TrimSpace(key)

	startOfString := strings.Index(value, "'")
	if startOfString < 0 {
		return
	}
	endOfString := strings.LastIndex(value, "'")
	if endOfString < 0 {
		return
	}
	value = value[startOfString+1 : endOfString]

	// Now we match the javascript variables with our struct variables and convert
	switch {
	case key == "js_SerialNumber":
		s.SerialNumber = value
	case key == "js_FWVersion":
		s.FirmwareVersion = value
	case key == "js_HWTypeVersion":
		s.HardwareType = value
	case key == "js_UptimeSinceReboot":
		values := strings.Split(value, ",")
		dur, err := time.ParseDuration(fmt.Sprintf("%sh%sm%ss", values[0], values[1], values[2]))
		if err != nil {
			return
		}
		s.Uptime = dur
	case key == "js_DateTime":
		t, err := time.Parse("02.01.2006 | 15:04", value)
		if err != nil {
			return
		}
		s.CurrentTime = t
	case key == "js_WANMACAddress":
		mac, err := net.ParseMAC(value)
		if err != nil {
			return
		}
		s.WanInterface.MacAddress = mac
	case key == "js_ipv4addr":
		s.WanInterface.Ipv4Address = net.ParseIP(value)
	case key == "js_ipv6addr":
		s.WanInterface.Ipv6Address = net.ParseIP(value)
	case key == "js_LANMACADDRESS":
		mac, err := net.ParseMAC(value)
		if err != nil {
			return
		}
		s.LanInterface.MacAddress = mac
	case key == "js_ipv4LANaddr", key == "js_ipv6LANprefix":
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return
		}
		if key == "js_ipv4LANaddr" {
			s.LanInterface.Ipv4Address = network
		} else {
			s.LanInterface.Ipv6Address = network
		}
	case key == "js_ipv4gateway":
		s.LanInterface.Ipv4Gateway = net.ParseIP(value)
	case port.MatchString(key):
		m := port.FindStringSubmatch(key)
		name := "Port " + m[1]
		subkey := m[2]

		arrayI := 0

		// Search whether we have already seen this port
		for i := range s.LanInterface.LANPorts {
			if s.LanInterface.LANPorts[i].Name == name {
				arrayI = i
				goto found
			}
		}

		// We have not seen it, append a new port with the name
		s.LanInterface.LANPorts = append(s.LanInterface.LANPorts, Port{Name: name})
		arrayI = len(s.LanInterface.LANPorts) - 1

	found:
		switch subkey {
		case "status":
			switch value {
			case "Active":
				s.LanInterface.LANPorts[arrayI].Enabled = true
			case "Inactive":
				s.LanInterface.LANPorts[arrayI].Enabled = false
			}
		case "bitrate":
			switch value {
			case "100 Mbps":
				s.LanInterface.LANPorts[arrayI].Bitrate = 100
			case "1 Gbps":
				s.LanInterface.LANPorts[arrayI].Bitrate = 1000
			}
		}

	case wlanEnable.MatchString(key):
		enabled := false
		if value == "On" {
			enabled = true
		}

		if m := wlanEnable.FindStringSubmatch(key); m[1] == "24" {
			s.WLAN24G.Enabled = enabled
		} else if m[1] == "5" {
			s.WLAN5G.Enabled = enabled
		}
	case wlanSSID.MatchString(key):
		if m := wlanSSID.FindStringSubmatch(key); m[1] == "24" {
			s.WLAN24G.SSID = value
		} else if m[1] == "5" {
			s.WLAN5G.SSID = value
		}
	case wlanMacAddress.MatchString(key):
		mac, err := net.ParseMAC(value)
		if err != nil {
			return
		}
		if m := wlanMacAddress.FindStringSubmatch(key); m[1] == "24" {
			s.WLAN24G.MacAddress = mac
		} else if m[1] == "5" {
			s.WLAN5G.MacAddress = mac
		}
	case wlanChannel.MatchString(key):
		channel, err := strconv.Atoi(value)
		if err != nil {
			return
		}
		if m := wlanChannel.FindStringSubmatch(key); m[1] == "24" {
			s.WLAN24G.Channel = uint(channel)
		} else if m[1] == "5" {
			s.WLAN5G.Channel = uint(channel)
		}
	case wlanSecurity.MatchString(key):
		if m := wlanSecurity.FindStringSubmatch(key); m[1] == "24" {
			s.WLAN24G.Security = value
		} else if m[1] == "5" {
			s.WLAN5G.Security = value
		}
	case wlanBandwidth.MatchString(key):
		bw, err := strconv.Atoi(value)
		if err != nil {
			return
		}
		if m := wlanBandwidth.FindStringSubmatch(key); m[1] == "24" {
			s.WLAN24G.Bandwidth = uint(bw)
		} else if m[1] == "5" {
			s.WLAN5G.Bandwidth = uint(bw)
		}
	}
}

func (v *Vodafone) StatusGet() (*Status, error) {
	if !v.loggedIn {
		return nil, NotLoggedInError
	}

	resp, err := v.Get("status_status_data.php")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var status Status

	scanner := bufio.NewScanner(resp.Body)

	for scanner.Scan() {
		status.fillStatusStruct(scanner.Text())
	}

	return &status, scanner.Err()
}

type dhcpLeaseResponse struct {
	DhcpDevInfo [][]any `json:"dhcpDevInfo"`
}

type DhcpLease struct {
	Hostname    string
	MacAddress  net.HardwareAddr
	Ipv4Address net.IP
	DhcpType    string
	State       bool
	Valid       time.Duration
}

func (d DhcpLease) String() string {
	return fmt.Sprintf("%s (%s): %s, %s, %t, %s", d.Hostname, d.MacAddress.String(), d.Ipv4Address.String(), d.DhcpType, d.State, d.Valid.String())
}

func (v *Vodafone) DhcpLeaseGet() ([]DhcpLease, error) {
	if !v.loggedIn {
		return nil, NotLoggedInError
	}
	resp, err := v.Get("status_lan_data.php", `lanData[dhcpDevInfo]=`)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	var dR dhcpLeaseResponse
	if err := json.Unmarshal(body, &dR); err != nil {
		return nil, err
	}

	res := make([]DhcpLease, len(dR.DhcpDevInfo))

	for i, dev := range dR.DhcpDevInfo {
		res[i].Hostname = dev[0].(string)
		res[i].MacAddress, err = net.ParseMAC(dev[1].(string))
		if err != nil {
			return nil, err
		}
		res[i].Ipv4Address = net.ParseIP(dev[2].(string))
		res[i].DhcpType = dev[3].(string)
		if state, ok := dev[4].(string); ok && state == "true" { // true is "true" and false is false????
			res[i].State = true
		} else if state, ok := dev[4].(bool); ok {
			res[i].State = state
		} else {
			return nil, fmt.Errorf("Could not parse response")
		}
		durations := strings.SplitSeq(dev[5].(string), ",")
		for dur := range durations {
			if strings.Contains(dur, "d") {
				days, err := strconv.Atoi(dur[:len(dur)-1])
				if err != nil {
					return nil, err
				}
				parsedDays, err := time.ParseDuration(strconv.Itoa(24*days) + "d")
				if err != nil {
					return nil, err
				}
				res[i].Valid += parsedDays
			} else {
				parsed, err := time.ParseDuration(dur)
				if err != nil {
					return nil, err
				}
				res[i].Valid += parsed
			}
		}
	}

	return res, nil
}
