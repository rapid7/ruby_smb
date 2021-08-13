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

domain_sid = samr.samr_lookup_domain(server_handle: server_handle, name: domain)
domain_handle = samr.samr_open_domain(server_handle: server_handle, domain_id: domain_sid)

builtin_domain_sid = samr.samr_lookup_domain(server_handle: server_handle, name: 'Builtin')
builtin_domain_handle = samr.samr_open_domain(server_handle: server_handle, domain_id: builtin_domain_sid)

users = samr.samr_enumerate_users_in_domain(domain_handle: domain_handle)

puts 'RID   | SID                                         | Name          | Domain Groups | Domain Alias Groups | Builtin Alias Groups'
puts '--------------------------------------------------------------------------------------------------------------------------------'
users.each do |rid, name|
  sid = samr.samr_rid_to_sid(object_handle: domain_handle, rid: rid)
  domain_sid = sid.to_s.split('-')[0..-2].join('-')

  user_handle = samr.samr_open_user(domain_handle: domain_handle, user_id: rid)
  groups = samr.samr_get_group_for_user(user_handle: user_handle)
  groups = groups.map { |group| RubySMB::Dcerpc::Samr::RpcSid.new("#{domain_sid}-#{group.relative_id.to_i}") }

  alias_groups = samr.samr_get_alias_membership(domain_handle: domain_handle, sids: groups + [sid])
  alias_groups = alias_groups.map { |group| RubySMB::Dcerpc::Samr::RpcSid.new("#{domain_sid}-#{group}") }

  builtin_alias_groups = samr.samr_get_alias_membership(domain_handle: builtin_domain_handle, sids: groups + [sid])
  builtin_alias_groups = builtin_alias_groups.map { |group| RubySMB::Dcerpc::Samr::RpcSid.new("#{domain_sid}-#{group}") }

  #TODO: implement [LSAT] LsarLookupSids2 call to get the name of the "Unknown SID"'s

  output = "#{"%-5s" % rid} | #{"%-43s" % sid} | #{name.encode('UTF-8')}"
  output << " | #{groups.empty? ? 'N/A' : groups.map(&:name).join(', ')}"
  output << " | #{alias_groups.empty? ? 'N/A' : alias_groups.map(&:name).join(', ')}"
  output << " | #{builtin_alias_groups.empty? ? 'N/A' : builtin_alias_groups.map(&:name).join(', ')}"
  puts output

  samr.close_handle(user_handle)
end

samr.close_handle(domain_handle)
samr.close_handle(builtin_domain_handle)
samr.close_handle(server_handle)

client.disconnect!

