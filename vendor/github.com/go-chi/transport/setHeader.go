package transport

import (
	"net/http"
)

func SetHeader(header string, value string) func(http.RoundTripper) http.RoundTripper {
	return func(next http.RoundTripper) http.RoundTripper {
		return RoundTripFunc(func(req *http.Request) (resp *http.Response, err error) {
			r := CloneRequest(req)

			r.Header.Set(http.CanonicalHeaderKey(header), value)

			return next.RoundTrip(r)
		})
	}
}
