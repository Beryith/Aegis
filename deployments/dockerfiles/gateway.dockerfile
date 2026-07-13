FROM golang:1.25-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o gateway ./cmd/gateway/

FROM alpine:latest

WORKDIR /app
COPY --from=builder /build/gateway .

EXPOSE 8080

CMD ["./gateway"]
