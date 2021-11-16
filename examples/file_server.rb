#!/usr/bin/ruby

require 'bundler/setup'
require 'ruby_smb'
require 'ruby_smb/gss/provider/ntlm'

ntlm_provider = RubySMB::Gss::Provider::NTLM.new(allow_anonymous: true)
ntlm_provider.put_account('RubySMB', 'password')  # password can also be an NTLM hash

server = RubySMB::Server.new(
  gss_provider: ntlm_provider
)
puts "server is running"
server.run do
  puts "received connection"
  true
end

