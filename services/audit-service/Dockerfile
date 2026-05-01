FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.work go.work.sum* ./
COPY pkg/ pkg/
COPY services/audit-service/ services/audit-service/
RUN go build -ldflags="-s -w" -o /bin/audit-service ./services/audit-service/...

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/audit-service /bin/audit-service
EXPOSE 8083
ENTRYPOINT ["/bin/audit-service"]
