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
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"encoding/hex"
	"encoding/json"

	"github.com/hbuschbaum/vodafone-station/crypto"
)

type Vodafone struct {
	host      string
	client    http.Client
	sessionId string
	nonce     string
	csrfNonce string
	iv        string
	salt      string
	key       []byte
	cookie    string
	loggedIn  bool
}

// Returns a new [Vodafone] instance given a host.
func NewVodafone(host string) *Vodafone {
	v := &Vodafone{
		host:     host,
		client:   http.Client{Jar: nil},
		loggedIn: false,
	}
	return v
}

func (v *Vodafone) fillHeader(h *http.Header) {
	h.Add("X-Requested-With", "XMLHttpRequest")
	h.Add("Referer", v.host+"/?overview")
	h.Add("Origin", v.host)
	h.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64)")
	if v.cookie != "" {
		h.Add("Cookie", v.cookie)
	}
	if v.csrfNonce != "" {
		h.Add("csrfNonce", v.csrfNonce)
	}
}

// Get triggers a GET request for the given endpoint. At most one params may be given.
// This value is then appended as a query parameter.
func (v *Vodafone) Get(endpoint string, params ...string) (*http.Response, error) {
	realParams := ""
	if len(params) == 1 {
		realParams = "&" + url.QueryEscape(params[0])
	} else if len(params) > 1 {
		return nil, fmt.Errorf("At most one parameter allowed")
	}
	req, err := http.NewRequest("GET", v.host+"/php/"+endpoint+"?_n="+v.nonce+realParams, nil)
	if err != nil {
		return nil, err
	}
	v.fillHeader(&req.Header)
	return v.client.Do(req)
}

func (v *Vodafone) putPost(method string, endpoint string, data io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, v.host+"/php/"+endpoint+"?_n="+v.nonce, data)
	if err != nil {
		return nil, err
	}
	v.fillHeader(&req.Header)
	return v.client.Do(req)
}

// Put triggers a PUT request on a given [Vodafone] instance. The data is sent as is to the given endpoint.
func (v *Vodafone) Put(endpoint string, data io.Reader) (*http.Response, error) {
	return v.putPost("PUT", endpoint, data)
}

// Post triggers a Post request on a given [Vodafone] instance. The data is sent as is to the given endpoint.
func (v *Vodafone) Post(endpoint string, data io.Reader) (*http.Response, error) {
	return v.putPost("POST", endpoint, data)
}

func (v *Vodafone) initCrypto() error {
	resp, err := v.client.Get(v.host + "/") // request the root document
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	setCookieValues := resp.Header.Values("set-cookie")
	if len(setCookieValues) == 0 {
		return fmt.Errorf("Could not find required values (cookie)")
	}
	// extract session id
	v.sessionId = strings.Split(strings.Split(setCookieValues[0], "=")[1], ";")[0]
	v.cookie = "PHPSESSID=" + v.sessionId
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return err
	}
	// Find correct script tag
	// html -> head -> script (most likely the second script tag)
	var currNode *html.Node
	for n := range doc.Descendants() {
		if n.DataAtom == atom.Head {
			currNode = n
			break
		}
	}
	if currNode == nil {
		return fmt.Errorf("Could not find Head Node")
	}
	for n := range currNode.ChildNodes() {
		if n.DataAtom == atom.Script {
			currScript := n.FirstChild.Data
			if !strings.Contains(currScript, "myIv") { // this is not the right one
				continue
			}
			v.iv = strings.Split(strings.Split(currScript, "var myIv = '")[1], "';")[0]
			v.salt = strings.Split(strings.Split(currScript, "var mySalt = '")[1], "';")[0]
			nonce, _ := rand.Int(rand.Reader, big.NewInt(90000))
			v.nonce = strconv.Itoa(int(nonce.Int64()) + 10000) // 10000 - 99999
			return nil
		}
	}
	return fmt.Errorf("Could not find required values (script tag)")
}

func (v *Vodafone) setSession() error {
	resp, err := v.Post("ajaxSet_Session.php", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// here we could check whether the returned value is "yes"
	v.loggedIn = true
	return nil
}

type loginResponse struct {
	PStatus     string `json:"p_status"`
	EncryptData string `json:"encryptData"`
	WaitTime    int    `json:"p_waitTime"`
}

// Inititates a login request given the username and password. 
func (v *Vodafone) Login(username, password string) error {
	if v.loggedIn {
		return nil
	}

	if err := v.initCrypto(); err != nil { // initiate the crypto values which are sent from the vodafone station
		return err
	}
	jsData := fmt.Sprintf("{\"Password\": \"%s\", \"Nonce\": \"%s\"}", password, v.sessionId)
	var err error
	// get current session key derived from the user supplied password
	v.key, err = crypto.Pbkdf2(password, v.salt, crypto.DEFAULT_ITERATIONS, crypto.DEFAULT_KEYSIZEBYTES)
	if err != nil {
		return err
	}
	const authData string = "loginPassword"

	// encrypt the passwort and nonce with the derived key
	encryptedData, err := crypto.CCMencrypt(v.key, jsData, v.iv, authData, crypto.DEFAULT_TAGLENGTH)
	if err != nil {
		return err
	}
	//send the encrypted password to the vodafone station
	loginData := fmt.Sprintf("{\"EncryptData\":\"%s\",\"Name\":\"%s\",\"AuthData\":\"%s\"}", hex.EncodeToString(encryptedData), username, authData)
	resp, err := v.Post("ajaxSet_Password.php", strings.NewReader(loginData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var lresponse loginResponse
	if err := json.Unmarshal(body, &lresponse); err != nil {
		return err
	}

	// check the response status
	switch lresponse.PStatus {
	case "Fail":
		return fmt.Errorf("Login failed: Wrong Password")
	case "Lockout":
		return fmt.Errorf("Login failed: locked out for %d", lresponse.WaitTime)
	case "Match", "Default":
		setCookieValues := resp.Header.Values("set-cookie")
		if len(setCookieValues) == 0 {
			return fmt.Errorf("Could not find required values (cookie)")
		}
		v.sessionId = strings.Split(strings.Split(setCookieValues[0], "=")[1], ";")[0]
		v.cookie = "PHPSESSID=" + v.sessionId
		// the nonce is also sent encrypted, so decrypt it
		csrfNonce, err := crypto.CCMdecrypt(v.key, lresponse.EncryptData, v.iv, "nonce", crypto.DEFAULT_TAGLENGTH)
		if err != nil {
			return err
		}
		v.csrfNonce = string(csrfNonce)
		return v.setSession() // check if login was successful
	}
	return fmt.Errorf("Unknown p_status: %s", lresponse.PStatus)
}

// Requests a logout.
func (v *Vodafone) Logout() {
	v.Post("logout.php", nil)
	v.loggedIn = false
}

func (v *Vodafone) IsLoggedIn() bool {
	return v.loggedIn
}
