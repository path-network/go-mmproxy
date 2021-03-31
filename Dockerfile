FROM golang:1.15

ENV CGO_ENABLED=0
WORKDIR /go/src/app

COPY . .

RUN go build -v


FROM alpine:3

RUN apk add iptables ip6tables

COPY all-networks.txt .
COPY path-prefixes.txt .

COPY --from=0 /go/src/app/go-mmproxy .

ENTRYPOINT ["./go-mmproxy"]
