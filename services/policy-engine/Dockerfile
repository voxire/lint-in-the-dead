FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.work go.work.sum* ./
COPY pkg/ pkg/
COPY services/policy-engine/ services/policy-engine/
RUN go build -ldflags="-s -w" -o /bin/policy-engine ./services/policy-engine/...

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/policy-engine /bin/policy-engine
EXPOSE 8081
ENTRYPOINT ["/bin/policy-engine"]
