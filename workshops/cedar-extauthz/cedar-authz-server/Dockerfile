# Build the cedar-go ext_authz service.
FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /cedar-authz-server .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /cedar-authz-server /cedar-authz-server
# policies are mounted from a ConfigMap at /policies (see k8s/10-cedar-authz-deploy.yaml)
ENV CEDAR_POLICY=/policies/authz.cedar
ENV LISTEN_ADDR=:9090
EXPOSE 9090
USER nonroot:nonroot
ENTRYPOINT ["/cedar-authz-server"]
