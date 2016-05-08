package th_tools

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type Request struct{}

/**
 * Do a request to Requestor
 *
 * @params form
 * form := url.Values{}
 * form.Add("url", "http://google.nl")
**/
func (r Request) Do(method string, uri string, form url.Values) (int, []byte, error) {

	mTLSConfig := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	mTLSConfig.PreferServerCipherSuites = true
	mTLSConfig.MinVersion = tls.VersionTLS10
	mTLSConfig.MaxVersion = tls.VersionTLS10

	tr := &http.Transport{
		TLSClientConfig: mTLSConfig,
	}

	hc := &http.Client{Transport: tr}

	//log.Println(uri)
	//log.Println(form.Encode())

	var (
		req *http.Request
		err error
	)

	if form != nil {
		req, err = http.NewRequest(method, uri, strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest(method, uri, nil)
	}

	if err != nil {
		return 0, nil, err
	}

	response, err := hc.Do(req)

	defer response.Body.Close()

	if err != nil {
		return 0, nil, err
	}

	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return 0, nil, err
	}

	return response.StatusCode, contents, nil
}
