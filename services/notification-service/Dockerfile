FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.work go.work.sum* ./
COPY pkg/ pkg/
COPY services/notification-service/ services/notification-service/
RUN go build -ldflags="-s -w" -o /bin/notification-service ./services/notification-service/...

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/notification-service /bin/notification-service
EXPOSE 8084
ENTRYPOINT ["/bin/notification-service"]
