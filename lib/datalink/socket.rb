# frozen_string_literal: true

require "socket" # load stdlib ::Socket before we define Datalink::Socket
require "datalink/error"
require "datalink/backends/base"

module Datalink
  # The front door for live layer-2 capture and injection.
  #
  #   Datalink::Socket.open("eth0") do |sock|
  #     sock.recv_timeout = 2
  #     frame = sock.recv.frame
  #     sock.send(my_frame)
  #   end
  #
  # By default it picks a backend from the host OS (AF_PACKET on Linux,
  # BPF on macOS/BSD). You can force a backend for testing or offline
  # work:
  #
  #   Datalink::Socket.new("lo", backend: :loopback)
  #   Datalink::Socket.new("file.pcap", backend: :pcap_file, mode: :read)
  #
  # Backends are required lazily, so loading this file never pulls in a
  # platform backend you are not using.
  class Socket
    # Explicit backend selection beyond the OS default:
    # symbol => [require path, class name].
    BACKENDS = {
      linux: ["datalink/backends/linux", "Linux"],
      bpf: ["datalink/backends/bpf", "BPF"],
      loopback: ["datalink/backends/loopback", "Loopback"],
      pcap_file: ["datalink/backends/pcap_file", "PcapFile"]
    }.freeze

    class << self
      # Open a socket, yield it, and close it afterward (even on error).
      # Without a block, returns an open socket the caller must close.
      def open(interface, **opts)
        sock = new(interface, **opts).tap(&:open)
        return sock unless block_given?

        begin
          yield sock
        ensure
          sock.close
        end
      end

      # The backend class the current host would use by default.
      def default_backend_class
        require "datalink/backends/linux"
        require "datalink/backends/bpf"
        return Backends::Linux if Backends::Linux.available?
        return Backends::BPF if Backends::BPF.available?

        raise UnsupportedPlatform,
              "no live datalink backend for #{RUBY_PLATFORM}; " \
              "use backend: :loopback or :pcap_file, or install one that fits your OS"
      end
    end

    attr_reader :backend

    def initialize(interface, backend: nil, recv_timeout: nil, **backend_opts)
      klass = backend_class(backend)
      @backend = klass.new(interface, recv_timeout: recv_timeout, **backend_opts)
    end

    def open
      @backend.open
      self
    end

    def open?
      @backend.open?
    end

    def interface
      @backend.interface
    end

    def recv_timeout
      @backend.recv_timeout
    end

    def recv_timeout=(seconds)
      @backend.recv_timeout = seconds
    end

    # Receive one frame as a CapturedFrame (call .frame on it to parse).
    def recv
      @backend.recv
    end

    # Receive and parse in one step.
    def recv_frame
      @backend.recv.frame
    end

    # Send raw bytes, a Frame, or anything with #encode.
    def send(obj)
      @backend.send(obj)
    end

    def close
      @backend.close
    end

    # Yield each captured frame until the block breaks, the capture ends,
    # or (with a recv_timeout set) nothing arrives in time.
    def each_frame
      return enum_for(:each_frame) unless block_given?

      loop do
        yield recv.frame
      rescue TimeoutError
        break
      end
    end

    private

    def backend_class(selector)
      case selector
      when nil
        self.class.default_backend_class
      when Symbol
        entry = BACKENDS[selector]
        raise ArgumentError, "unknown backend #{selector.inspect}" if entry.nil?

        path, const = entry
        require path
        Backends.const_get(const)
      when Class
        selector
      else
        raise ArgumentError, "backend must be a Symbol or Class, got #{selector.class}"
      end
    end
  end
end
