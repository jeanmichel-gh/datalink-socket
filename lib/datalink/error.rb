# frozen_string_literal: true

module Datalink
  # Base class for every error this library raises.
  class Error < StandardError; end

  # Raised when a value cannot be parsed into the expected wire form
  # (a malformed MAC string, a truncated frame, a bad ARP packet).
  class ParseError < Error; end

  # Raised when a MAC or IP address string is not valid.
  class AddressError < ParseError; end

  # Raised when no live backend exists for the host OS, or a required
  # native dependency (such as Npcap on Windows) is missing.
  class UnsupportedPlatform < Error; end

  # Raised when a socket operation needs privileges the process lacks.
  class PermissionError < Error; end

  # Raised when a blocking receive exceeds its timeout.
  class TimeoutError < Error; end
end
