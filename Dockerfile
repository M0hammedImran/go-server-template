#build stage
FROM golang:alpine AS builder
RUN apk add --no-cache git make
WORKDIR /go/src/app
COPY . .
RUN go get -d -v ./...
RUN go build -ldflags '-s -w' -o /go/bin/app -v cmd/router/main.go

#final stage
FROM alpine:latest
ARG CONFIG_PATH
ARG AWS_S3_ACCESS_KEY
ARG AWS_S3_SECRET_KEY
ARG AWS_S3_REGION
ARG AWS_S3_BUCKET
ARG AWS_S3_CONFIG_OBJECT_KEY

ENV CONFIG_PATH=$CONFIG_PATH
ENV AWS_S3_ACCESS_KEY=$AWS_S3_ACCESS_KEY
ENV AWS_S3_SECRET_KEY=$AWS_S3_SECRET_KEY
ENV AWS_S3_REGION=$AWS_S3_REGION
ENV AWS_S3_BUCKET=$AWS_S3_BUCKET
ENV AWS_S3_CONFIG_OBJECT_KEY=$AWS_S3_CONFIG_OBJECT_KEY

RUN apk --no-cache add ca-certificates
COPY --from=builder /go/bin/app /app
COPY --from=builder /go/src/app/configs/local.yaml /configs/local.yaml
ENTRYPOINT /app
LABEL Name=bywatt Version=0.0.1
EXPOSE 9090
