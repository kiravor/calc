FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc make pkg-config libssl-dev libcurl4-openssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN make -C sparta -j2

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libcurl4 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/sparta /etc/sparta \
    && chown 10001:10001 /var/lib/sparta
COPY --from=build /src/sparta/build/sparta /usr/local/bin/sparta
USER 10001:10001
VOLUME ["/var/lib/sparta"]
ENTRYPOINT ["/usr/local/bin/sparta"]
CMD ["node", "--config", "/etc/sparta/node.json"]
