#!/usr/bin/ruby

#
# This script is for testing the Protocol Negotiation in the library
# without any other parts.

require 'bundler/setup'
require 'ruby_smb'

def run_negotiation(address, smb1, smb2, smb3)
  # Create our socket and add it to the dispatcher
  sock = TCPSocket.new address, 445
  dispatcher = RubySMB::Dispatcher::Socket.new(sock)

  client = RubySMB::Client.new(dispatcher, smb1: smb1, smb2: smb2, smb3: smb3, username: 'test', password: '123456')
  client.negotiate(encryption: true, compression: true, servername: 'servertest')
end

# Negotiate with only SMB2 enabled
run_negotiation(ARGV[0], true, false, true)
