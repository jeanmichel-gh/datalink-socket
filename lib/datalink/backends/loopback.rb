# frozen_string_literal: true

require "datalink/backends/base"

module Datalink
  module Backends
    # An in-memory backend with no OS involvement. Frames you send land
    # in a shared "wire"; frames on the wire can be received. Pair two
    # loopback backends on the same Wire to simulate two hosts on a
    # segment, with no privileges and no real NIC.
    #
    #   wire = Loopback::Wire.new
    #   a = Loopback.new("a", wire: wire)
    #   b = Loopback.new("b", wire: wire)
    #   a.open; b.open
    #   a.send(frame)
    #   b.recv.frame   #=> the frame a sent
    #
    # This is the backbone of the functional tests: ARP, RARP, spoofing
    # and the poisoning attack can all be exercised over it.
    class Loopback < Base
      # A shared broadcast medium. Each attached endpoint gets its own
      # receive queue; a sent frame is copied to every *other* endpoint,
      # matching how a hub (or a switch flooding) behaves.
      class Wire
        def initialize
          @queues = {}
          @mutex = Mutex.new
          @cond = ConditionVariable.new
        end

        def attach(endpoint)
          @mutex.synchronize { @queues[endpoint] ||= [] }
        end

        def detach(endpoint)
          @mutex.synchronize { @queues.delete(endpoint) }
        end

        def transmit(from, bytes, timestamp)
          @mutex.synchronize do
            @queues.each do |endpoint, queue|
              next if endpoint.equal?(from)

              queue << CapturedFrame.new(bytes.b, timestamp)
            end
            @cond.broadcast
          end
        end

        # Block until +endpoint+ has a frame or +timeout+ elapses.
        # Returns the frame or nil on timeout.
        def receive(endpoint, timeout)
          deadline = timeout && (now + timeout)
          @mutex.synchronize do
            loop do
              queue = @queues[endpoint]
              raise Error, "endpoint detached from wire" if queue.nil?
              return queue.shift unless queue.empty?

              if deadline
                remaining = deadline - now
                return nil if remaining <= 0

                @cond.wait(@mutex, remaining)
              else
                @cond.wait(@mutex)
              end
            end
          end
        end

        private

        def now
          Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end
      end

      attr_reader :wire

      def initialize(interface = "lo0", wire: Wire.new, recv_timeout: nil)
        super(interface, recv_timeout: recv_timeout)
        @wire = wire
      end

      def open
        @wire.attach(self)
        @open = true
        self
      end

      def recv
        ensure_open
        captured = @wire.receive(self, @recv_timeout)
        raise TimeoutError, "no frame within #{@recv_timeout}s" if captured.nil?

        captured
      end

      def close
        @wire.detach(self)
        @open = false
      end

      private

      def do_send(bytes)
        ensure_open
        @wire.transmit(self, bytes, Time.now)
        bytes.bytesize
      end

      def ensure_open
        raise Error, "backend not open" unless @open
      end
    end
  end
end
