# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'smb2/version'

Gem::Specification.new do |spec|
  spec.name          = "smb2"
  spec.version       = Smb2::VERSION
  spec.authors       = ["James Lee"]
  spec.email         = ["egypt@metasploit.com"]
  spec.summary       = %q{A message creator and parser for the SMB2 protocol}
  spec.description   = %q{}
  spec.homepage      = "http://www.metasploit.com"
  spec.license       = "BSD-3-clause"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.7"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"

  spec.add_runtime_dependency "rubyntlm"
  spec.add_runtime_dependency "bit-struct"

end
