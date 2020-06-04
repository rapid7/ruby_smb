#!/usr/bin/ruby

#
# This script is for testing the Protocol Negotiation in the library
# without any other parts.

require 'bundler/setup'
require 'ruby_smb'

def run_negotiation(address, smb1, smb2, smb3, opts = {})
  # Create our socket and add it to the dispatcher
  sock = TCPSocket.new address, 445
  dispatcher = RubySMB::Dispatcher::Socket.new(sock)

  client = RubySMB::Client.new(dispatcher, smb1: smb1, smb2: smb2, smb3: smb3, username: 'msfadmin', password: 'msfadmin')
  client.negotiate
end

begin
  puts "Negotiate with only SMB1 enabled..."
  puts "  Negotiated version: #{run_negotiation(ARGV[0], true, false, false)}"
rescue RubySMB::Error::RubySMBError => e
  puts "Error: #{e.message}"
end

begin
  puts "Negotiate with only SMB2 enabled..."
  puts "  Negotiated version: #{run_negotiation(ARGV[0], false, true, false)}"
rescue RubySMB::Error::RubySMBError => e
  puts "Error: #{e.message}"
end

begin
  puts "Negotiate with only SMB3 enabled..."
  puts "  Negotiated version: #{run_negotiation(ARGV[0], false, false, true)}"
rescue RubySMB::Error::RubySMBError => e
  puts "Error: #{e.message}"
end

begin
  puts "Negotiate with both SMB1 and SMB2 enabled on the client..."
  puts "  Negotiated version: #{run_negotiation(ARGV[0], true, true, false)}"
rescue RubySMB::Error::RubySMBError => e
  puts "Error: #{e.message}"
end

begin
  puts "Negotiate with both SMB2 and SMB3 enabled on the client..."
  puts "  Negotiated version: #{run_negotiation(ARGV[0], false, true, true)}"
rescue RubySMB::Error::RubySMBError => e
  puts "Error: #{e.message}"
end

begin
  puts "Negotiate with both SMB1 and SMB3 enabled on the client..."
  puts "  Negotiated version: #{run_negotiation(ARGV[0], true, false, true)}"
rescue RubySMB::Error::RubySMBError => e
  puts "Error: #{e.message}"
end

begin
  puts "Negotiate with SMB1, SMB2 and SMB3 enabled on the client..."
  puts "  Negotiated version: #{run_negotiation(ARGV[0], true, true, true)}"
rescue RubySMB::Error::RubySMBError => e
  puts "Error: #{e.message}"
end

