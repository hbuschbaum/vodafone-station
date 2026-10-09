package vodafone

import (
	"fmt"

	"go.mdl.wtf/go-macaddr"
)

// Returns whether a given macAddress is present in the list of exposed hosts.
// It does not state whether the found rule is enabled.
func (v *Vodafone) HostExposureContainsMac(macAddress *macaddr.MACAddress) (bool, error) {
	hosts, err := v.HostExposureGet()
	if err != nil {
		return false, err
	}

	for _, e := range hosts {
		if e.MacAddress.Equal(macAddress) {
			return true, nil
		}
	}
	return false, nil
}

// Returns whether a given name is present in the list of exposed hosts.
// It does not state whether the found rule is enabled.
func (v *Vodafone) HostExposureContainsName(name string) (bool, error) {
	rq, err := v.getRawHostsAndNames()
	if err != nil {
		return false, err
	}

	var macs []*macaddr.MACAddress // this is an array since several hosts could have the same name
	for _, host := range rq.DhcpClient {
		if name == host[0] {
			mac, err := macaddr.ParseMACAddress(host[1]) // save the mac address for this host
			if err != nil {
				return false, err
			}
			macs = append(macs, mac)
			break
		}
	}
	if len(macs) == 0 {
		return false, nil // there is no host with the given name
	}

	for _, mac := range macs {
		for _, e := range rq.HostExposure {
			hostMac, err := macaddr.ParseMACAddress(e.MacAddress)
			if err != nil {
				return false, err
			}
			if hostMac.Equal(mac) {
				return true, nil // we have found one match. Thats enough, we return
			}
		}
	}

	return false, nil // we have found no match
}

// Appends an [ExposedHost] to the list of exposed hosts. Any set [ExposedHost.Index] will be overwritten by tge correct one.
func (v *Vodafone) HostExposureAppend(exposedHost ExposedHost) error {
	if !v.loggedIn {
		return &NotLoggedInError{}
	}

	hosts, err := v.HostExposureGet()
	if err != nil {
		return err
	}

	maxIndex := 0
	for _, h := range hosts {
		if h.Index > maxIndex {
			maxIndex = h.Index
		}
	}

	exposedHost.Index = maxIndex + 1
	hosts = append(hosts, exposedHost)

	return v.HostExposureSet(hosts)
}

// Appends the stated rule to the exposed hosts. The host is identified via its macAddress.
func (v *Vodafone) HostExposureAppendRuleByMac(ruleName string, macAddress *macaddr.MACAddress, startPort int, endPort int, protocol ProtocolType, enabled bool) error {
	host := ExposedHost{
		0,
		ruleName,
		enabled,
		startPort,
		endPort,
		macAddress,
		protocol,
	}

	return v.HostExposureAppend(host)
}

// Appends the stated rule to the exposed hosts. The host is identified via its hostname. If multiple hosts exist with the same hostname an error is returned.
func (v *Vodafone) HostExposureAppendRuleByName(ruleName string, hostname string, startPort int, endPort int, protocol ProtocolType, enabled bool) error {
	rq, err := v.getRawHostsAndNames()
	if err != nil {
		return err
	}

	var mac *macaddr.MACAddress
	for _, host := range rq.DhcpClient {
		if host[0] == hostname {
			if mac != nil {
				return fmt.Errorf("Multiple hosts with the same name exist")
			}
			mac, err = macaddr.ParseMACAddress(host[1])
		}
	}

	return v.HostExposureAppendRuleByMac(ruleName, mac, startPort, endPort, protocol, enabled)
}
