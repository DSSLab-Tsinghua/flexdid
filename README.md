# Redactable PS Anonymous Identity

Codebase for the following paper: 

Yunqing Bian, Xin Wang, Jian Jin, Zhenzhen Jiao, and Sisi Duan. Flexible and Scalable Decentralized Identity Management for Industrial Internet of Things. IEEE Internet of Things Journal, 2024

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
