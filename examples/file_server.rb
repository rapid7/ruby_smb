#!/usr/bin/ruby

require 'bundler/setup'
require 'ruby_smb'
require 'ruby_smb/gss/provider/ntlm'

ntlm_provider = RubySMB::Gss::Provider::NTLM.new(allow_anonymous: true)
ntlm_provider.put_account('RubySMB', 'password')

server = RubySMB::Server.new(
  gss_provider: ntlm_provider,
  shares: [
    RubySMB::Server::Share::Disk.new('public')
  ]
)
puts "server is running"
server.run do
  puts "received connection"
  true
end
