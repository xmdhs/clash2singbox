SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=arm64
go build -trimpath -ldflags "-w -s"
