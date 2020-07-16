#!/usr/bin/ruby

# This script is for testing the NetBIOS Session Service Request on port 139/tcp.
# Example usage: ruby negotiate.rb 192.168.172.138 NBNAME
# This will connect to 192.168.172.138 (139/TCP) and request a NetBIOS session with NBNAME as the called name. 
# If successful, a SMB negotiation is performed using this NetBIOS session.
# The default *SMBSERVER name is used if the NetBIOS name is not provided.

require 'bundler/setup'
require 'ruby_smb'

def run_negotiation(address, smb1, smb2, smb3, netbios_name)
  sock = TCPSocket.new address, 139
  dispatcher = RubySMB::Dispatcher::Socket.new(sock)

  client = RubySMB::Client.new(dispatcher, smb1: smb1, smb2: smb2, smb3: smb3, username: 'msfadmin', password: 'msfadmin')
  begin
    client.session_request(netbios_name)
  rescue RubySMB::Error::NetBiosSessionService => e
    puts "NetBIOS Session refused with #{netbios_name}: #{e.message}"
    return
  end
  puts "NetBIOS Session granted with #{netbios_name}, negotiating..."
  smb_version = client.negotiate
  puts "#{smb_version} successfully negotiated."
end

address      = ARGV[0]
netbios_name = ARGV[1] || '*SMBSERVER'

# Negotiate with SMB1, SMB2 and SMB3 enabled on the client
run_negotiation(ARGV[0], true, true, true, netbios_name)
# Negotiate with both SMB1 and SMB2 enabled on the client
run_negotiation(ARGV[0], true, true, false, netbios_name)
# Negotiate with only SMB1 enabled
run_negotiation(ARGV[0], true, false, false, netbios_name)
# Negotiate with only SMB2 enabled
run_negotiation(ARGV[0], false, true, false, netbios_name)
# Negotiate with only SMB3 enabled
run_negotiation(ARGV[0], false, false, true, netbios_name)
