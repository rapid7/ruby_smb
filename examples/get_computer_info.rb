#!/usr/bin/ruby

# This example script is used for testing DCERPC WKST requests.
# It will attempt to retrieve configuration information of a remote computer/server.
# Example usage: ruby enum_domain_users.rb 192.168.172.138 msfadmin msfadmin MyDomain

require 'bundler/setup'
require 'ruby_smb'

address      = ARGV[0]
username     = ARGV[1]
password     = ARGV[2]
smb_versions = ARGV[3]&.split(',') || ['1','2','3']

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock, read_timeout: 60)

client = RubySMB::Client.new(dispatcher, smb1: smb_versions.include?('1'), smb2: smb_versions.include?('2'), smb3: smb_versions.include?('3'), username: username, password: password)
protocol = client.negotiate
status = client.authenticate

puts "#{protocol} : #{status}"

tree = client.tree_connect("\\\\#{address}\\IPC$")
wkssvc = tree.open_file(filename: 'wkssvc', write: true, read: true)

puts('Binding to \\wkssvc...')
wkssvc.bind(endpoint: RubySMB::Dcerpc::Wkssvc)
puts('Bound to \\wkssvc')

puts('[+] WKSSVC Connect')

info = wkssvc.netr_wksta_get_info
platform = RubySMB::Dcerpc::Wkssvc::PLATFORM_ID[info.wki100_platform_id]
puts "Platform: #{platform || 'Unknown'}"
puts "Computer Name: #{info.wki100_computername.encode('utf-8')}"
puts "LAN Group: #{info.wki100_langroup.encode('utf-8')}"
puts "OS Version: #{info.wki100_ver_major}.#{info.wki100_ver_minor}"

client.disconnect!


