#!/usr/bin/ruby

# This example script is used for testing DCERPC SAMR requests.
# It will attempt to connect to a server object and enumerate domain users.
# Example usage: ruby enum_domain_users.rb --username msfadmin --password msfadmin 192.168.172.138 MyDomain

require 'bundler/setup'
require 'optparse'
require 'ruby_smb'

args = ARGV.dup
options = {
  domain: '.',
  username: '',
  password: '',
  smbv1: true,
  smbv2: true,
  smbv3: true,
  target: nil,
  lookup_domain: nil
}
options[:lookup_domain] = args.pop
options[:target] = args.pop
optparser = OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename(__FILE__)} [options] target domain"
  opts.on("--[no-]smbv1", "Enable or disable SMBv1 (default: #{options[:smbv1] ? 'Enabled' : 'Disabled'})") do |smbv1|
    options[:smbv1] = smbv1
  end
  opts.on("--[no-]smbv2", "Enable or disable SMBv2 (default: #{options[:smbv2] ? 'Enabled' : 'Disabled'})") do |smbv2|
    options[:smbv2] = smbv2
  end
  opts.on("--[no-]smbv3", "Enable or disable SMBv3 (default: #{options[:smbv3] ? 'Enabled' : 'Disabled'})") do |smbv3|
    options[:smbv3] = smbv3
  end
  opts.on("--username USERNAME", "The account's username (default: #{options[:username]})") do |username|
    if username.include?('\\')
      options[:domain], options[:username] = username.split('\\', 2)
    else
      options[:username] = username
    end
  end
  opts.on("--password PASSWORD", "The account's password (default: #{options[:password]})") do |password|
    options[:password] = password
  end
end
optparser.parse!(args)

if [options[:target], options[:lookup_domain]].any? { |a| a == '-h' || a == '--help' }
  puts optparser.help
  exit
end

if options[:target].nil? || options[:lookup_domain].nil?
  abort(optparser.help)
end

address = options[:target]
domain = options[:lookup_domain]

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock, read_timeout: 60)

client = RubySMB::Client.new(dispatcher, smb1: options[:smbv1], smb2: options[:smbv2], smb3: options[:smbv3], username: options[:username], password: options[:password], domain: options[:domain])
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
