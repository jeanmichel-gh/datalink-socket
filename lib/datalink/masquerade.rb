# frozen_string_literal: true

require "open3"
require "datalink/mac"
require "datalink/error"

module Datalink
  # Change (masquerade) and restore an interface's hardware MAC address.
  #
  # Two senses of "masquerade" apply at layer 2, and this class is the
  # first: rewriting your own NIC's MAC so frames you originate carry it.
  # (The other sense, forging the source MAC inside individual crafted
  # frames, needs no OS change -- just set Frame#src; see Spoof.)
  #
  # ------------------------------------------------------------------
  #  Changing your MAC needs root/administrator. Do it only on hardware
  #  and networks you are authorized to use. Some networks treat MAC
  #  changes as a policy violation.
  # ------------------------------------------------------------------
  #
  #   m = Datalink::Masquerade.new("eth0")
  #   original = m.current               # => MAC
  #   m.set("02:11:22:33:44:55")         # or m.randomize
  #   # ... do your thing ...
  #   m.restore                          # back to the original
  #
  # Implemented with the platform's own tools (`ip link` on Linux,
  # `ifconfig` on macOS/BSD). Windows MAC changes go through the registry
  # or a driver and are out of scope here.
  class Masquerade
    def initialize(interface)
      @interface = interface
      @original = nil
    end

    # The interface's current MAC, read from the OS.
    def current
      case os
      when :linux  then read_mac_linux
      when :macos, :bsd then read_mac_bsd
      else raise UnsupportedPlatform, "cannot read MAC on #{RUBY_PLATFORM}"
      end
    end

    # Set the interface MAC. Remembers the original on first call so
    # #restore can put it back.
    def set(mac)
      mac = mac.is_a?(MAC) ? mac : MAC.new(mac)
      @original ||= current
      case os
      when :linux then set_mac_linux(mac)
      when :macos, :bsd then set_mac_bsd(mac)
      else raise UnsupportedPlatform, "cannot set MAC on #{RUBY_PLATFORM}"
      end
      mac
    end

    # Set a random locally-administered unicast MAC.
    def randomize
      set(MAC.random)
    end

    # Put the original MAC back. No-op if we never changed it.
    def restore
      return nil if @original.nil?

      set_without_tracking(@original)
      restored = @original
      @original = nil
      restored
    end

    private

    def set_without_tracking(mac)
      case os
      when :linux then set_mac_linux(mac)
      when :macos, :bsd then set_mac_bsd(mac)
      end
    end

    # --- Linux: ip link ---

    def read_mac_linux
      out = run("ip", "-o", "link", "show", "dev", @interface)
      m = out[/link\/ether\s+([0-9a-f:]{17})/i, 1]
      raise Error, "could not read MAC of #{@interface}" unless m

      MAC.new(m)
    end

    def set_mac_linux(mac)
      run("ip", "link", "set", "dev", @interface, "down")
      run("ip", "link", "set", "dev", @interface, "address", mac.to_s)
      run("ip", "link", "set", "dev", @interface, "up")
    end

    # --- macOS / BSD: ifconfig ---

    def read_mac_bsd
      out = run("ifconfig", @interface)
      m = out[/(?:ether|lladdr)\s+([0-9a-f:]{17})/i, 1]
      raise Error, "could not read MAC of #{@interface}" unless m

      MAC.new(m)
    end

    def set_mac_bsd(mac)
      # macOS wants the interface associated-down for Wi-Fi; for wired,
      # a plain ifconfig ether works.
      run("ifconfig", @interface, "ether", mac.to_s)
    end

    # --- helpers ---

    def run(*cmd)
      stdout, stderr, status = Open3.capture3(*cmd)
      unless status.success?
        msg = stderr.strip.empty? ? stdout.strip : stderr.strip
        raise PermissionError, "#{cmd.first} failed (need root?): #{msg}" if msg =~ /permission|not permitted|denied/i

        raise Error, "#{cmd.join(' ')} failed: #{msg}"
      end
      stdout
    end

    def os
      @os ||=
        case RUBY_PLATFORM
        when /linux/ then :linux
        when /darwin/ then :macos
        when /bsd/ then :bsd
        else :unknown
        end
    end
  end
end
