# Image for the datalink-socket command-line tools (arp-scan, arp-spoof).
#
# The gem itself is a Ruby library; this image exists so the CLIs can run
# without a local Ruby setup. Raw layer 2 from a container is limited:
# the tools need both NET_RAW and the host network to see real traffic.
#
#   docker build -t datalink-socket .
#   docker run --rm --net=host --cap-add=NET_RAW datalink-socket \
#     arp-scan -i eth0 -s 192.168.1.10 -m 00:11:22:33:44:55 192.168.1.0/24
#
FROM ruby:3.3-slim

LABEL org.opencontainers.image.source="https://github.com/jeanmichel-gh/datalink-socket" \
      org.opencontainers.image.description="Layer-2 Ethernet toolkit: datalink socket, ARP/RARP, spoof/MITM CLIs" \
      org.opencontainers.image.licenses="Ruby"

WORKDIR /src
COPY . .

# Build and install the gem, then drop the source. No native extensions,
# so no build toolchain is needed.
RUN gem build datalink-socket.gemspec \
    && gem install --local --no-document ./datalink-socket-*.gem \
    && rm -rf /src

WORKDIR /
CMD ["sh", "-c", "echo 'datalink-socket: run arp-scan or arp-spoof.'; echo 'Needs --net=host --cap-add=NET_RAW. See https://github.com/jeanmichel-gh/datalink-socket'"]
