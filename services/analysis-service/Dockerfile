FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.work go.work.sum* ./
COPY pkg/ pkg/
COPY services/analysis-service/ services/analysis-service/
RUN go build -ldflags="-s -w" -o /bin/analysis-service ./services/analysis-service/...

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata git
COPY --from=builder /bin/analysis-service /bin/analysis-service
EXPOSE 8082
ENTRYPOINT ["/bin/analysis-service"]
