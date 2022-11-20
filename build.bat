SET CGO_ENABLED=0
SET GOOS=windows
SET GOARCH=amd64
SET GOAMD64=v3
go build -trimpath -ldflags "-w -s"
