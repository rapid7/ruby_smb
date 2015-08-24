# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ruby_smb/version'

Gem::Specification.new do |spec|
  spec.name          = "ruby_smb"
  spec.version       = RubySMB::GEM_VERSION
  spec.authors       = ["James Lee"]
  spec.email         = ["egypt@metasploit.com"]
  spec.summary       = %q{A message creator and parser for the SMB protocol family}
  spec.description   = %q{}
  spec.homepage      = "http://www.metasploit.com"
  spec.license       = "BSD-3-clause"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  if RUBY_PLATFORM =~ /java/
    spec.add_development_dependency "kramdown"
    spec.platform = Gem::Platform::JAVA
  else
    spec.add_development_dependency "redcarpet"
    spec.platform = Gem::Platform::RUBY
  end

  spec.add_development_dependency "bundler", "~> 1.7"
  spec.add_development_dependency "fivemat"
  spec.add_development_dependency "metasploit-version"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "yard"
  spec.add_development_dependency "yard-bit-struct"

  spec.add_runtime_dependency "rubyntlm", "~> 0.5"
  spec.add_runtime_dependency "bit-struct"
  spec.add_runtime_dependency "windows_error"
  spec.add_runtime_dependency 'bindata'

end
