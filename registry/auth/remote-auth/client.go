package remote

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/bugsnag/bugsnag-go/errors"
)

const (
	maxErrMsgLen = 256
	userAgent    = "docket-private-registry"

	DefaultTimeout = 15*time.Second
)

type RemoteClient struct {
	cl      *http.Client
	apiUrl  string
	timeout time.Duration
}

func NewRemoteClient(cfg map[string]interface{}) (*RemoteClient, error) {
	var err error
	apiUrl, present := cfg["apiUrl"]
	if _, ok := apiUrl.(string); !present || !ok {
		return nil, fmt.Errorf(`"apiUrl" must be set for custom login`)
	}
	timeout := DefaultTimeout
	timeoutStr, present := cfg["timeout"]
	if _, ok := timeoutStr.(string); present && ok {
		timeout, err = time.ParseDuration(timeoutStr.(string))
		if err != nil {
			return nil, fmt.Errorf("failed to set remote client timeout: %v",err)
		}
	}

	cl := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        20000,
			MaxIdleConnsPerHost: 1000, // see https://github.com/golang/go/issues/13801
			DisableKeepAlives:   false,
			DisableCompression:  true,
			// 5 minutes is typically above the maximum sane scrape interval. So we can
			// use keepalive for all configurations.
			IdleConnTimeout:       5 * time.Minute,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DialContext:(&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
		},
	}
	return &RemoteClient{
		cl:      cl,
		apiUrl:  apiUrl.(string),
		timeout: timeout,
	}, nil
}

func (r *RemoteClient) RemoteRequest(username, password string, req []byte) (int, error) {
	httpReq, err := http.NewRequest("POST", r.apiUrl, bytes.NewReader(req))
	if err != nil {
		// Errors from NewRequest are from unparseable URLs, so are not
		// recoverable.
		return 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", userAgent)
	httpReq.SetBasicAuth(username, password)

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	httpResp, err := r.cl.Do(httpReq.WithContext(ctx))
	if err != nil {
		return 0, err
	}
	defer func() {
		io.Copy(ioutil.Discard, httpResp.Body)
		httpResp.Body.Close()
	}()

	if httpResp.StatusCode/100 != 2 {
		scanner := bufio.NewScanner(io.LimitReader(httpResp.Body, maxErrMsgLen))
		line := ""
		if scanner.Scan() {
			line = scanner.Text()
		}
		err = errors.Errorf("server returned HTTP status %s: %s", httpResp.Status, line)
	}
	return httpResp.StatusCode, err
}
