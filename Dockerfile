FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 go build -o main .

FROM alpine:latest
WORKDIR /app

RUN apk add --no-cache \
    chromium \
    nss \
    freetype \
    harfbuzz \
    ca-certificates \
    ttf-freefont
    
COPY --from=builder /app/main .

COPY --from=builder /app/templates ./templates

EXPOSE 8080

CMD ["./main"]
