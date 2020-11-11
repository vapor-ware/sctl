FROM vaporio/golang:1.13 as BUILD
COPY . /sctl
WORKDIR /sctl
RUN go build -ldflags "-linkmode external -extldflags -static"

FROM scratch
COPY --from=0 /sctl/sctl /bin/sctl
ENTRYPOINT ["/bin/sctl"]
