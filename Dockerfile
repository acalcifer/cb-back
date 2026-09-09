# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS build
WORKDIR /src

# Dependencies first: this layer is cached until go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO_ENABLED=0 produces a static binary, which is what lets the final image
# be distroless. -trimpath keeps build paths out of the binary.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# distroless static has no shell, no package manager and no libc: a code
# execution bug in the server finds nothing to pivot to. :nonroot runs as
# uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/server /server
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/server"]
