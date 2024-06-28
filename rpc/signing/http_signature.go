package signing

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
)

var labelRegex = regexp.MustCompile("^[a-zA-Z0-9-_]+$")

var knownHeaders = map[string]bool{
	"content-digest": true,
}

type httpSignatureBuilder struct {
	signer Signer
	body   []byte
	header http.Header
	status int
	req    *http.Request

	label  string
	fields []string
	nonce  string
	alg    Algorithm
}

func newHTTPSignatureBuilder(signer Signer, body []byte, req *http.Request, resHeader http.Header, status int) (*httpSignatureBuilder, error) {
	b := &httpSignatureBuilder{
		signer: signer,
		body:   body,
		header: resHeader,
		req:    req,
		status: status,
	}

	if err := b.parseAcceptSignature(req.Header.Get("accept-signature")); err != nil {
		return nil, err
	}

	fieldsToInclude := []string{"content-digest"}
	for _, field := range fieldsToInclude {
		if !slices.Contains(b.fields, field) {
			b.fields = append(b.fields, field)
		}
	}

	return b, nil
}

func (b *httpSignatureBuilder) parseAcceptSignature(headerValue string) error {
	dict, err := httpsfv.UnmarshalDictionary([]string{headerValue})
	if err != nil {
		return err
	}

	if len(dict.Names()) != 1 {
		return fmt.Errorf("expected exactly 1 dictionary item")
	}

	b.label = dict.Names()[0]
	if !labelRegex.MatchString(b.label) || b.label == "" || len(b.label) > 16 {
		return fmt.Errorf("invalid label %q", b.label)
	}

	member, _ := dict.Get(b.label)
	il, ok := member.(httpsfv.InnerList)
	if !ok {
		return fmt.Errorf("expected inner list")
	}

	for _, item := range il.Items {
		val, ok := item.Value.(string)
		if !ok {
			return fmt.Errorf("expected string as inner list value")
		}
		field := strings.TrimSpace(strings.ToLower(val))

		if b.getFieldValue(field) == "" && !knownHeaders[field] {
			return fmt.Errorf("unknown header %q", field)
		}

		b.fields = append(b.fields, field)
	}

	if il.Params != nil {
		if nonce, ok := il.Params.Get("nonce"); ok {
			if nonceVal, ok := nonce.(string); ok {
				if !labelRegex.MatchString(nonceVal) || len(nonceVal) > 64 {
					return fmt.Errorf("invalid nonce %q", nonceVal)
				}
				b.nonce = nonceVal
			}
		}

		if alg, ok := il.Params.Get("alg"); ok {
			algVal, _ := alg.(string)
			b.alg, err = NewAlgorithm(algVal)
			if err != nil {
				return err
			}
		}
		if !b.alg.IsValid() {
			b.alg = AlgorithmRsaPkcs1V15Sha256
		}
	}

	return nil
}

func (b *httpSignatureBuilder) Generate(ctx context.Context) error {
	digest, contentLen, err := b.generateDigest()
	if err != nil {
		return err
	}

	sigInput, err := b.signatureParams()
	if err != nil {
		return err
	}

	h := b.header
	if h.Get("Date") == "" {
		h.Add("Date", time.Now().UTC().Format(http.TimeFormat))
	}
	if h.Get("Content-Length") == "" {
		h.Add("Content-Length", strconv.Itoa(contentLen))
	}
	h.Add("Content-Digest", digest)

	sigBytes, err := b.generateSignature(ctx, sigInput)
	if err != nil {
		return err
	}

	dict := httpsfv.NewDictionary()
	dict.Add("sig", httpsfv.NewItem(sigBytes))
	sigValue, err := httpsfv.Marshal(dict)
	if err != nil {
		return err
	}

	h.Add("Signature-Input", fmt.Sprintf("sig=%s", sigInput))
	h.Add("Signature", sigValue)
	return nil
}

func (b *httpSignatureBuilder) signatureParams() (string, error) {
	il := httpsfv.InnerList{
		Items:  make([]httpsfv.Item, 0),
		Params: httpsfv.NewParams(),
	}

	for _, h := range b.fields {
		il.Items = append(il.Items, httpsfv.Item{
			Value:  strings.ToLower(h),
			Params: httpsfv.NewParams(),
		})
	}

	il.Params.Add("created", time.Now().Unix())
	il.Params.Add("keyid", b.signer.KeyID())
	il.Params.Add("alg", b.alg.String())

	if b.nonce != "" {
		il.Params.Add("nonce", b.nonce)
	}

	return httpsfv.Marshal(il)
}

func (b *httpSignatureBuilder) generateDigest() (string, int, error) {
	dict := httpsfv.NewDictionary()
	s := sha256.New()
	contentLen, err := s.Write(b.body)
	if err != nil {
		return "", 0, err
	}
	dict.Add("sha-256", httpsfv.NewItem(s.Sum(nil)[:]))
	res, err := httpsfv.Marshal(dict)
	if err != nil {
		return "", 0, err
	}
	return res, int(contentLen), nil
}

func (b *httpSignatureBuilder) generateSignature(ctx context.Context, sigParams string) ([]byte, error) {
	input := make([]string, 0)
	for _, field := range b.fields {
		v := b.getFieldValue(field)
		input = append(input, fmt.Sprintf(`"%s": %s`, strings.ToLower(field), v))
	}
	input = append(input, fmt.Sprintf(`"@signature-params": %s`, sigParams))
	sigBase := strings.Join(input, "\n")

	sig, err := b.signer.Sign(ctx, b.alg, []byte(sigBase))
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (b *httpSignatureBuilder) getFieldValue(key string) string {
	switch key {
	case "@method":
		return b.req.Method
	case "@path":
		return b.req.URL.Path
	case "@scheme":
		return b.req.URL.Scheme
	case "@target-uri":
		return strings.TrimSuffix("https://"+b.req.Host+b.req.URL.Path, "/")
	case "@authority":
		return b.req.Host
	case "@status":
		return strconv.Itoa(b.status)
	default:
		return b.header.Get(key)
	}
}
