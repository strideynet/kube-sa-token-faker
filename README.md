# kube-sa-token-faker

Need a JWT in the style of a Kubernetes Projected Service Account Token? And a
valid JWKS endpoint to go with it?

This is the extremely niche do-not-use-in-production tool for you!

Example:

```shell
$ go run ./ --audience example.com \
  --pod-name my-lovely-pod \
  --namespace not-default \
  --service-account bar \
  --output-dir /opt/fakek8s
```

This will write three files to `/opt/fakek8s`:

- `token`: a JWT signed with a key from the JWKS endpoint
- `jwks.json`: a JWKS that contains the public key used to sign the JWTs
- `private-key.pem`: the private key used to sign the JWTs

The JWT will have a TTL of 5 minutes, and will be regenerated each minute.

You can specify `--oneshot` to generate the token once and exit.