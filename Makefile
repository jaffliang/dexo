.PHONY: setup generate clean build-doh-gateway

setup:
	mise install && mise x -- tuist install && ./scripts/build-doh-gateway.sh && mise x -- tuist generate

generate:
	mise x -- tuist generate

build-doh-gateway:
	./scripts/build-doh-gateway.sh

clean:
	mise x -- tuist clean
	rm -rf Native/DoHGateway/dist Native/DoHGateway/target
