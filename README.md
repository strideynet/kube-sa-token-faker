# kube-sa-token-faker

Need a JWT in the style of a Kubernetes Projected Service Account Token? And a
valid JWKS endpoint to go with it?

This is the extremely niche do-not-use-in-production tool for you!

Example:

```shell
$ go run ./ --audience example.com --pod-name my-lovely-pod --namespace not-default --service-account bar --output-dir /opt/fakek8s
```