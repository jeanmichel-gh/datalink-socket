# frozen_string_literal: true

require "datalink/error"

module Datalink
  module Backends
    # A frame as it came off a backend: the raw bytes plus the time it
    # was captured. Returned by Backend#recv.
    CapturedFrame = Struct.new(:bytes, :timestamp) do
      # Parse the bytes into a Datalink::Frame (lazy; requires frame.rb).
      def frame
        require "datalink/frame"
        @frame ||= Datalink::Frame.parse(bytes)
      end

      def to_s
        bytes.b
      end
    end

    # The contract every backend implements. A backend is a byte pipe for
    # one interface: open it, receive raw frames, send raw frames, close.
    #
    # Subclasses must implement #open, #recv, #do_send, #close. The
    # facade (Datalink::Socket) selects and drives one of these.
    class Base
      # @return [String] the interface name this backend is bound to
      attr_reader :interface

      # @return [Float, nil] seconds to block in #recv before raising
      #   TimeoutError; nil means block indefinitely.
      attr_accessor :recv_timeout

      def initialize(interface, recv_timeout: nil)
        @interface = interface
        @recv_timeout = recv_timeout
        @open = false
      end

      def open
        raise NotImplementedError, "#{self.class}#open"
      end

      def open?
        @open
      end

      # Receive one frame. Returns a CapturedFrame, or raises TimeoutError
      # if recv_timeout elapses first.
      def recv
        raise NotImplementedError, "#{self.class}#recv"
      end

      # Send raw bytes, or any object that responds to #encode.
      # @return [Integer] bytes written
      def send(obj)
        bytes = obj.respond_to?(:encode) ? obj.encode : obj
        do_send(bytes.b)
      end

      def close
        raise NotImplementedError, "#{self.class}#close"
      end

      private

      def do_send(_bytes)
        raise NotImplementedError, "#{self.class}#do_send"
      end
    end
  end
end
