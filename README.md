# Redactable PS Anonymous Identity

## How to run project

```
cd RedactablePSIdentity
go env -w GO111MODULE=off
export GOPATH=$PWD && export GOBIN=$PWD/bin
```

```
go install src/main/main.go
```

```
bin/main issuer-keygen
bin/main userconfig
bin/main derive-aggregate
```