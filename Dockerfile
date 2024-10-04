FROM golang:1.22 as builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o sti-ct .

FROM scratch

COPY --from=builder /app/sti-ct /sti-ct

ENTRYPOINT ["/sti-ct"]
