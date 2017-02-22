#!/usr/bin/ruby

require 'bundler/setup'
require 'ruby_smb'

# Do Multi-Protocol Negotiation

# Create the initial SMB! Negotiate Request packet
smb1_negotiate_request_packet = RubySMB::SMB1::Packet::NegotiateRequest.new
smb1_negotiate_request_packet.add_dialect('NT LM 0.12')
smb1_negotiate_request_packet.add_dialect('SMB 2.002')
smb1_negotiate_request_packet.add_dialect('SMB 2.???')

smb2 = false
# Go ahead and setup the SMB2 Negotiate request packet so we have it ready
smb2_negotiate_request_packet = RubySMB::SMB2::Packet::NegotiateRequest.new
smb2_negotiate_request_packet.add_dialect(0x0202)
smb2_negotiate_request_packet.add_dialect(0x0210)
smb2_negotiate_request_packet.smb2_header.message_id = 1

# Create our socket and add it to the dispatcher
sock = TCPSocket.new '192.168.172.138', 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock)

puts 'Sending SMB1 Negotiate Request Packet:'
puts '======================================'
puts smb1_negotiate_request_packet.display

dispatcher.send_packet smb1_negotiate_request_packet
negotiate_response_raw1 = dispatcher.recv_packet

# Check to see if the response is an SMB1 or SMB2 Negotiate Response
negotiate_response1 = RubySMB::SMB1::Packet::NegotiateResponse.read negotiate_response_raw1
unless negotiate_response1.smb_header.command == 0x72
  smb2 = true
  negotiate_response1 = RubySMB::SMB2::Packet::NegotiateResponse.read negotiate_response_raw1
end

puts 'Received Negotiate Response Packet:'
puts '======================================'
puts negotiate_response1.display

if smb2
  puts 'Sending SMB2 Negotiate Request Packet:'
  puts '======================================'
  puts smb1_negotiate_request_packet.display
  dispatcher.send_packet smb2_negotiate_request_packet
  negotiate_response_raw2 = dispatcher.recv_packet
  negotiate_response2 = RubySMB::SMB2::Packet::NegotiateResponse.read negotiate_response_raw2

  puts 'Received Negotiate Response Packet:'
  puts '======================================'
  puts negotiate_response2.display
end