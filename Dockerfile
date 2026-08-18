FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /pawstash-sync ./cmd/pawstash-sync

FROM alpine:3.22
RUN addgroup -S pawstash && adduser -S -G pawstash pawstash && mkdir /data && chown pawstash:pawstash /data
COPY --from=build /pawstash-sync /usr/local/bin/pawstash-sync
USER pawstash
ENV PAWSTASH_SYNC_ADDR=0.0.0.0:8787 PAWSTASH_SYNC_DB=/data/sync.db
VOLUME ["/data"]
EXPOSE 8787
ENTRYPOINT ["pawstash-sync"]
