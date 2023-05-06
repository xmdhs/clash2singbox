SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=arm
SET GOARM=7
go build -trimpath -ldflags "-w -s"
