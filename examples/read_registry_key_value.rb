#!/usr/bin/ruby

# This example script is used for testing the Winreg registry key value read functionality.
# It will attempt to connect to a host and reads the value of a specified registry key.
# Example usage: ruby enum_registry_key.rb 192.168.172.138 msfadmin msfadmin HKLM\\My\\Key ValueName
# This will try to connect to \\192.168.172.138 with the msfadmin:msfadmin credentialas and reads the ValueName data corresponding to the HKLM\\My\\Key registry key.

require 'bundler/setup'
require 'ruby_smb'

address  = ARGV[0]
username = ARGV[1]
password = ARGV[2]
registry_key = ARGV[3]
value_name = ARGV[4]

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock, read_timeout: 60)

client = RubySMB::Client.new(dispatcher, smb1: true, smb2: true, username: username, password: password)
protocol = client.negotiate
status = client.authenticate

puts "#{protocol}: #{status}"
puts "Key:   #{registry_key}"
puts "Value: #{value_name}"

key_value = client.read_registry_key_value(address, registry_key, value_name)
puts key_value

client.disconnect!

