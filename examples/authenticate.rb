#!/usr/bin/ruby

# This script tests a full Authentication/Session Setup cycle
# including protocol negotiation and authentication.

require 'bundler/setup'
require 'ruby_smb'


def run_authentication(address, smb1, smb2, username, password)
  # Create our socket and add it to the dispatcher
  sock = TCPSocket.new address, 445
  dispatcher = RubySMB::Dispatcher::Socket.new(sock)

  client = RubySMB::Client.new(dispatcher, smb1: smb1, smb2: smb2, username: username, password: password)
  protocol = client.negotiate
  status  = client.authenticate
  if client.peer_native_os
    native_os = "(#{client.peer_native_os})"
  else
    native_os = ''
  end
  puts "#{protocol} : #{status} #{native_os}"
end

address  = ARGV[0]
username = ARGV[1]
password = ARGV[2]

# Negotiate with both SMB1 and SMB2 enabled on the client
run_authentication(address, true, true, username, password)
# Negotiate with only SMB1 enabled
run_authentication(address, true, false, username, password)
# Negotiate with only SMB2 enabled
run_authentication(address, false, true, username, password)
