# signing

This package implements a subset of [HTTP Signatures (RFC 9421)](https://datatracker.ietf.org/doc/rfc9421/). It allows the client to request the response to be signed by the enclave's KMS signing key.

## Client verification flow

For example, this is the simplest valid header that the client might send to request the signature:

```
Accept-Signature: sig=()
```

_NOTE: the header can be used to configure the signing behaviour. E.g. to negotiate another signing algorithm: `Accept-Signature: sig=();alg="rsa-pss-sha512"`_

The server will respond with the following additional response headers:

```
Content-Digest: sha-256=:iEOQW4XMC7cWjTsRlcG1Z7HgQMbMOdoS4ReAPLYdZjg=:
Signature: sig=:rHQRHLetRueIDVa0sxA5DhxRwKfG7Vz38s7P9ueC+la5UoeOvkJuHc0ZKGKfxtZSZzvhX+xH2u1J7BjHt5/+zdz+uuqZr/e5JeOYpIqQ+8p0t/CRdpfH2OF6ZOZ1ZqBCaQqeYIfG/0BtVymhCNJLTR83+3ldnN+3yLVDVixT6mgcSIdrD8W0Rb9le6ctc4NSTZIx711uNMx+RsY7Ia6z+zvJhS6Y55wLZo+JZxpxbj2RnQralSAkFWcMwS3OgYyN413y1YiYOJ3q9AOeGPgqM4qjSQv9MQSY62d6ed0K3jPXQfFxwKLZ/n/GKaj7DjClYEpCCgbABq9QWXMfzYotpA==:
Signature-Input: sig=("content-digest");created=1718206167;keyid="bhTaEfhw-YEb-ttC1b-RSQ";alg="rsa-v1_5-sha256"
```

In order to verify the signature the client performs the following operations:

1. Calculate the response body digest using SHA-256. Compare it with the value found in the `Content-Digest` header (it's contained within the two `:` and base64-encoded).
2.  If the digest does not match, fail the verification.
3. Create the following buffer (signature base), replacing the placeholders `{Content-Digest}` and `{Signature-Input}` with the response header values:

```
"content-digest": {Content-Digest}
"@signature-params": {Signature-Input}
```

For example:

```
"content-digest": sha-256=:iEOQW4XMC7cWjTsRlcG1Z7HgQMbMOdoS4ReAPLYdZjg=:
"@signature-params": sig=("content-digest");created=1718206167;keyid="bhTaEfhw-YEb-ttC1b-RSQ";alg="rsa-v1_5-sha256"
```

4. Verify that the signature in the response (contained in the `Signature` response header, between the two `:` and base64-encoded) is correct, using the embedded public key and the RSA PKCS # 1 v1.5 SHA-256 algorithm where the message input is the signature base created previously.

