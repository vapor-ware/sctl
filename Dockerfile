FROM scratch
COPY sctl /bin/sctl
ENTRYPOINT ["/bin/sctl"]
