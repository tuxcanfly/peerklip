peerklip:
	go build

arm:
	env GOOS=linux GOARCH=arm GOARM=5 go build

clean:
	rm peerklip

.PHONY: arm
