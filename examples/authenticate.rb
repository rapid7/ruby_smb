#!/usr/bin/ruby

# This script tests a full Authentication/Session Setup cycle
# including protocol negotiation and authentication.

require 'bundler/setup'
require 'optparse'
require 'ruby_smb'

def run_authentication(address, smb1, smb2, smb3, username, password, domain)
  # Create our socket and add it to the dispatcher
  sock = TCPSocket.new address, 445
  dispatcher = RubySMB::Dispatcher::Socket.new(sock)

  client = RubySMB::Client.new(dispatcher, smb1: smb1, smb2: smb2, smb3: smb3, username: username, password: password, domain: domain)
  protocol = client.negotiate
  status = client.authenticate
  puts "#{protocol} : #{status}"
  if protocol == 'SMB1'
    puts "Native OS: #{client.peer_native_os}"
    puts "Native LAN Manager: #{client.peer_native_lm}"
  end
  puts "Netbios Name: #{client.default_name}"
  puts "Netbios Domain: #{client.default_domain}"
  puts "FQDN of the computer: #{client.dns_host_name}"
  puts "FQDN of the domain: #{client.dns_domain_name}"
  puts "FQDN of the forest: #{client.dns_tree_name}"
  puts "Dialect: #{client.dialect}"
  puts "OS Version: #{client.os_version}"
end

args = ARGV.dup
options = {
  domain: '.',
  username: '',
  password: '',
  smbv1: true,
  smbv2: true,
  smbv3: true,
  target: nil
}
options[:target] = args.pop
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

if options[:target] == '-h' || options[:target] == '--help'
  puts optparser.help
  exit
end

if options[:target].nil?
  abort(optparser.help)
end

# (smb1, smb2, smb3) combinations to exercise — filtered by the user's
# --[no-]smbv{1,2,3} flags so that any combo requiring a disabled version
# is skipped.
combinations = [
  [true,  true,  true],   # SMB1, SMB2 and SMB3 enabled
  [true,  true,  false],  # SMB1 and SMB2 enabled
  [true,  false, false],  # only SMB1 enabled
  [false, true,  false],  # only SMB2 enabled
  [false, false, true]    # only SMB3 enabled
]

combinations.each do |smb1, smb2, smb3|
  next if smb1 && !options[:smbv1]
  next if smb2 && !options[:smbv2]
  next if smb3 && !options[:smbv3]
  run_authentication(options[:target], smb1, smb2, smb3, options[:username], options[:password], options[:domain])
end
