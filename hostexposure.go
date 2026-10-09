/*
Vodafone-Station
Copyright (C) 2026  hbuschbaum

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package vodafone

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go.mdl.wtf/go-macaddr"
	"io"
	"strconv"
)

type hostExposureEntry struct {
	EndPort   string `json:"endPort"`
	Index     string `json:"index"`
	Protocol  string `json:"protocol"`
	StartPort string `json:"startPort"`
}

// A funny quirk of vodafone stations: different names for the same thing
// depending on whether you get the host exposure entry or set it
type requestedHostExposureEntry struct {
	hostExposureEntry
	Status     string `json:"Status"`
	MacAddress string `json:"MAC"`
	Name       string `json:"ServiceName"`
}

type sendHostExposureEntry struct {
	hostExposureEntry
	Status     string `json:"enable"`
	MacAddress string `json:"macAddress"`
	Name       string `json:"name"`
}

type dhcpClientEntry []string

type requestedHostExposure struct {
	HostExposure []requestedHostExposureEntry `json:"hostExposure"`
	DhcpClient   []dhcpClientEntry            `json:"dhcpclient"`
}

type setHostExposure struct {
	HEditRule []sendHostExposureEntry `json:"hEditRule"`
}

// Models the possible protocol types
type ProtocolType int

const (
	// Only TCP
	TCP ProtocolType = iota
	// Only UDP
	UDP
	// UDP and TCP
	Both
)

var protocolTypeMap = map[ProtocolType]string{
	TCP:  "TCP",
	UDP:  "UDP",
	Both: "BOTH",
}

var protocolTypeReverseMap = map[string]ProtocolType{
	"TCP":  TCP,
	"UDP":  UDP,
	"BOTH": Both,
}

// Converts the enum value ProtocolType to a string
func (pt ProtocolType) String() string {
	return protocolTypeMap[pt]
}

// Converts a string value to a ProtocolType.
// If the string cannot be converted to a ProtocolType an error is returned
func ParseProtocolType(str string) (ProtocolType, error) {
	pt, ok := protocolTypeReverseMap[str]
	if !ok {
		return 0, fmt.Errorf("Unknown protocol type %s", str)
	}
	return pt, nil
}

// Models the information necessary for the host exposure
type ExposedHost struct {
	Index      int
	Name       string
	Enabled    bool
	StartPort  int
	EndPort    int
	MacAddress *macaddr.MACAddress
	Protocol   ProtocolType
}

func parseExposedHost(e requestedHostExposureEntry) (ExposedHost, error) {
	index, err := strconv.Atoi(e.Index)
	if err != nil {
		return ExposedHost{}, err
	}

	startPort, err := strconv.Atoi(e.StartPort)
	if err != nil {
		return ExposedHost{}, err
	}

	endPort, err := strconv.Atoi(e.EndPort)
	if err != nil {
		return ExposedHost{}, err
	}

	enabled := false
	switch e.Status {
	case "Enabled":
		enabled = true
	case "Disabled":
		enabled = false
	default:
		return ExposedHost{}, fmt.Errorf("Could not parse enable field")
	}

	protocol, err := ParseProtocolType(e.Protocol)
	if err != nil {
		return ExposedHost{}, err
	}

	mac, err := macaddr.ParseMACAddress(e.MacAddress)
	if err != nil {
		return ExposedHost{}, err
	}

	return ExposedHost{
		index, e.Name, enabled, startPort, endPort, mac, protocol,
	}, nil
}

func makeNetworkHostExposure(e ExposedHost) sendHostExposureEntry {
	var enable string
	if e.Enabled {
		enable = "Enabled"
	} else {
		enable = "Disabled"
	}

	return sendHostExposureEntry{
		hostExposureEntry{
			strconv.Itoa(e.EndPort),
			strconv.Itoa(e.Index),
			e.Protocol.String(),
			strconv.Itoa(e.StartPort),
		},
		enable,
		e.MacAddress.String(),
		e.Name,
	}
}

func (e ExposedHost) String() string {
	return fmt.Sprintf("%d: %s (%s), %s %d-%d (%t)", e.Index, e.Name, e.MacAddress, e.Protocol.String(), e.StartPort, e.EndPort, e.Enabled)
}

func (v *Vodafone) getRawHostsAndNames() (requestedHostExposure, error) {
	if !v.loggedIn {
		return requestedHostExposure{}, &NotLoggedInError{}
	}

	resp, err := v.Get("net_ipv6_host_exposure_data.php", `{"hostExposure":{},"dhcpclient":{}}`)
	if err != nil {
		return requestedHostExposure{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return requestedHostExposure{}, err
	}

	var rq requestedHostExposure
	if err := json.Unmarshal(body, &rq); err != nil {
		return requestedHostExposure{}, err
	}
	return rq, nil
}

// Requests the list of exposed hosts from the vodafone station
func (v *Vodafone) HostExposureGet() ([]ExposedHost, error) {
	rq, err := v.getRawHostsAndNames()
	if err != nil {
		return nil, err
	}

	// convert the string values we receive from the station to correctly typed values
	ret := make([]ExposedHost, len(rq.HostExposure))
	for i, e := range rq.HostExposure {
		ret[i], err = parseExposedHost(e)
		if err != nil {
			return nil, err
		}
	}

	return ret, nil
}

// Sets the list of exposed hosts.
// This function does not append hosts, it overrides the current list.
func (v *Vodafone) HostExposureSet(exposedHosts []ExposedHost) error {
	if !v.loggedIn {
		return &NotLoggedInError{}
	}
	// convert the typed version of exposed hosts to the required only-string-values
	s := setHostExposure{
		make([]sendHostExposureEntry, len(exposedHosts)),
	}
	for i, e := range exposedHosts {
		s.HEditRule[i] = makeNetworkHostExposure(e)
	}

	marshalledS, err := json.Marshal(s)
	if err != nil {
		return err
	}

	r := bytes.NewReader(marshalledS)

	_, err = v.Post("ajaxSet_net_ipv6_host_exposure_data.php", r)
	return err
}
