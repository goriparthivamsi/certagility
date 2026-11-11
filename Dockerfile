FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /certagility ./cmd/certagility

FROM gcr.io/distroless/static:nonroot
COPY --from=build /certagility /certagility
USER nonroot
EXPOSE 9115
ENTRYPOINT ["/certagility"]
