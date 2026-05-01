FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.work go.work.sum* ./
COPY pkg/ pkg/
COPY services/api-gateway/ services/api-gateway/
RUN go build -ldflags="-s -w" -o /bin/api-gateway ./services/api-gateway/...

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/api-gateway /bin/api-gateway
EXPOSE 8080
ENTRYPOINT ["/bin/api-gateway"]
