rm -rf main.syso
rm -rf main.exe
rsrc -manifest main.exe.manifest -ico main.ico -o main.syso
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o main.exe