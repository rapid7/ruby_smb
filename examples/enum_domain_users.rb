#!/usr/bin/ruby

# This example script is used for testing DCERPC SAMR requests.
# It will attempt to connect to a server object and enumerate domain users.
# Example usage: ruby enum_domain_users.rb 192.168.172.138 msfadmin msfadmin MyDomain

require 'bundler/setup'
require 'ruby_smb'

address      = ARGV[0]
username     = ARGV[1]
password     = ARGV[2]
domain       = ARGV[3]
smb_versions = ARGV[4]&.split(',') || ['1','2','3']

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock, read_timeout: 60)

client = RubySMB::Client.new(dispatcher, smb1: smb_versions.include?('1'), smb2: smb_versions.include?('2'), smb3: smb_versions.include?('3'), username: username, password: password)
protocol = client.negotiate
status = client.authenticate

puts "#{protocol} : #{status}"

tree = client.tree_connect("\\\\#{address}\\IPC$")
samr = tree.open_file(filename: 'samr', write: true, read: true)

puts('Binding to \\samr...')
samr.bind(endpoint: RubySMB::Dcerpc::Samr)
puts('Bound to \\samr')

puts('[+] SAMR Connect')
server_handle = samr.samr_connect
sid = samr.samr_lookup_domain(server_handle: server_handle, name: domain)
domain_handle = samr.samr_open_domain(server_handle: server_handle, domain_id: sid)
users = samr.samr_enumerate_users_in_domain(domain_handle: domain_handle)
puts 'RID   | SID                                         | Name'
puts '----------------------------------------------------------'
users.each do |rid, name|
  sid = samr.samr_rid_to_sid(object_handle: domain_handle, rid: rid)
  puts "#{"%-5s" % rid} | #{"%-43s" % sid} | #{name.encode('UTF-8')}"
end

client.disconnect!

