# frozen_string_literal: true

require_relative "lib/datalink/version"

Gem::Specification.new do |spec|
  spec.name = "datalink-socket"
  spec.version = Datalink::VERSION
  spec.authors = ["Jean-Michel Esnault"]

  spec.summary = "Capture and inject raw Ethernet (layer 2) frames in Ruby, with ARP, RARP, and spoofing tools."
  spec.description = <<~DESC
    A pure-Ruby layer-2 toolkit: a datalink socket that captures and injects
    Ethernet frames on Linux (AF_PACKET) and macOS/BSD (BPF), value objects
    for MAC addresses and frames, ARP and RARP protocol implementations, and
    tooling for ARP spoofing, MAC masquerade, and a man-in-the-middle ARP
    cache-poisoning attack. Protocol and frame code need no privileges;
    loopback and pcap-file backends let the whole stack run in tests.
  DESC
  spec.homepage = "https://github.com/jeanmichel-gh/datalink-socket"
  spec.license = "Ruby"
  spec.required_ruby_version = ">= 3.1"

  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir[
    "lib/**/*.rb",
    "exe/*",
    "README.md",
    "CHANGELOG.md",
    "LICENSE*"
  ]
  spec.bindir = "exe"
  spec.executables = Dir["exe/*"].map { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rubocop", "~> 1.0"
end
