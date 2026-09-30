# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ruby_smb/version'

Gem::Specification.new do |spec|
  spec.name          = 'ruby_smb'
  spec.version       = RubySMB::VERSION
  spec.authors       = [
    'Metasploit Hackers',
    'David Maloney',
    'James Lee',
    'Dev Mohanty',
    'Christophe De La Fuente',
    'Spencer McIntyre'
  ]
  spec.email         = ['msfdev@metasploit.com']
  spec.summary       = 'A pure Ruby implementation of the SMB Protocol Family'
  spec.description   = ''
  spec.homepage      = 'https://github.com/rapid7/ruby_smb'
  spec.license       = 'BSD-3-clause'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  if RUBY_PLATFORM =~ /java/
    spec.add_development_dependency 'kramdown'
    spec.platform = Gem::Platform::JAVA
  else
    spec.add_development_dependency 'redcarpet'
    spec.platform = Gem::Platform::RUBY
  end

  spec.required_ruby_version = '>= 2.5'

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'fivemat'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'yard'

  spec.add_runtime_dependency 'rubyntlm', '>= 0.6.5'
  spec.add_runtime_dependency 'windows_error', '>= 0.1.4'
  spec.add_runtime_dependency 'bindata', '2.4.15'
  # 0.12 introduced the model `wrapper` DSL the SPNEGO types rely on; the upper Ruby versions resolve to a
  # newer rasn1, while Ruby 2.7 caps at 0.13.1 (0.14+ needs Ruby 3.0), and both are known good.
  spec.add_runtime_dependency 'rasn1', '>= 0.12'
  spec.add_runtime_dependency 'openssl-ccm'
  spec.add_runtime_dependency 'openssl-cmac'
end
