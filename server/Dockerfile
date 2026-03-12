FROM golang:1.24-alpine AS builder
WORKDIR /app/server
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server

FROM golang:1.24-alpine
WORKDIR /app
COPY --from=builder /app/server/server ./server
EXPOSE 8080
CMD ["./server"]
