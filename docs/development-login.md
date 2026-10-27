# Development administrator

Dev server builds include the default administrator `devadmin` with password
`devadmin`. This account has the same admin permissions as the configured
administrator and remains available when an existing administrator is present.
It uses normal expiring, revocable sessions and login rate limits. The configured
account and password are preserved. No plaintext credential is added to storage.

`make build` and Docker builds default to `BUILD_FLAVOR=dev`.
For native builds use `go build -tags dev ./cmd/server` (add `embedui` when
embedding the UI). A fresh dev workspace opens the login page directly; the
administrator setup API remains available for creating a personal account.

Build without the dev tag for deployment without the default login:

```sh
make build BUILD_FLAVOR=release
docker build --build-arg BUILD_FLAVOR=release -t codexploit:release .
```

Dev sessions use the same backing store as other sessions. Log out of dev
sessions before switching a shared workspace to a release binary; existing
sessions retain their normal expiry and revocation behavior.
