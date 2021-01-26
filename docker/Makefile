REGISTRY = docker.io
IMAGE_REPO = curiouser
IMAGE_NAME = openvpn-manager
IMAGE_VERSION = v1
all: build push
build:
		rm -rf statik target && statik -src=public
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o target/openvpn-manager main.go
		docker build --rm -f docker/Dockerfile -t ${REGISTRY}/${IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_VERSION} .
push:
		docker push ${REGISTRY}/${IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_VERSION}