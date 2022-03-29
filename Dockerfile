FROM golang:alpine as builder
ARG LDFLAGS=""

RUN apk update --no-cache && \
    apk add git build-base gcc pkgconfig zeromq-dev

COPY . /build
WORKDIR /build

RUN OUTPUT_NAME=dist/netflow2ng make

FROM alpine:latest
ARG src_dir

RUN apk update --no-cache && \
    apk add libzmq && \
    adduser -S -D -H -h / netflow
USER netflow
COPY --from=builder /build/dist/netflow2ng /

# ZMQ
EXPOSE 5556/tcp
# NetFlow v9
EXPOSE 2055/udp
# webserver
EXPOSE 8080/tcp
ENTRYPOINT ["/netflow2ng"]

