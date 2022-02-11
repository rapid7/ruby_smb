#!/usr/bin/ruby

# This script tests a full Authentication/Session Setup cycle
# including protocol negotiation and authentication.

require 'bundler/setup'
require 'optparse'
require 'ruby_smb'

def run_authentication(address, smb1, smb2, smb3)
  # Create our socket and add it to the dispatcher
  sock = TCPSocket.new address, 445
  dispatcher = RubySMB::Dispatcher::Socket.new(sock)

  client = RubySMB::Client.new(dispatcher, smb1: smb1, smb2: smb2, smb3: smb3, username: '', password: '')
  protocol = client.negotiate
  status = client.authenticate
  puts "#{protocol} : #{status}"
  if status.name == 'STATUS_SUCCESS'
    puts "Native OS: #{client.peer_native_os}"
    puts "Native LAN Manager: #{client.peer_native_lm}"
    puts "Domain/Workgroup: #{client.primary_domain}"
  end
end

args = ARGV.dup
options = {
  smbv1: true,
  smbv2: true,
  smbv3: true,
  target: nil
}
options[:target ] = args.pop
optparser = OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename(__FILE__)} [options] target"
  opts.on("--[no-]smbv1", "Enable or disable SMBv1 (default: #{options[:smbv1] ? 'Enabled' : 'Disabled'})") do |smbv1|
    options[:smbv1] = smbv1
  end
  opts.on("--[no-]smbv2", "Enable or disable SMBv2 (default: #{options[:smbv2] ? 'Enabled' : 'Disabled'})") do |smbv2|
    options[:smbv2] = smbv2
  end
  opts.on("--[no-]smbv3", "Enable or disable SMBv3 (default: #{options[:smbv3] ? 'Enabled' : 'Disabled'})") do |smbv3|
    options[:smbv3] = smbv3
  end
end
optparser.parse!(args)

if options[:target].nil?
  abort(optparser.help)
end

# Negotiate with only SMB1 enabled
run_authentication(options[:target], options[:smbv1], options[:smbv2], options[:smbv3])
