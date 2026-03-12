FROM golang:1.24-alpine AS builder
WORKDIR /app/client
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o client ./cmd/client

FROM golang:1.24-alpine
WORKDIR /app
COPY --from=builder /app/client/client ./client
COPY --from=builder /app/client/web ./web
EXPOSE 8081
CMD ["./client"]
