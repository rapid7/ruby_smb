#!/usr/bin/ruby

# This example script is used for testing Winreg registry key enumeration functionality
# It will attempt to connect to a host and enumerate registry subkeys of a specified registry key.
# Example usage: ruby enum_registry_key.rb --username msfadmin --password msfadmin 192.168.172.138 HKLM\\My\\Key
# This will try to connect to \\192.168.172.138 with the msfadmin:msfadmin credentialas and enumerate HKLM\\My\\Key subkeys.

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
  registry_key: nil
}
options[:registry_key] = args.pop
options[:target] = args.pop
optparser = OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename(__FILE__)} [options] target registry_key"
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

if [options[:target], options[:registry_key]].any? { |a| a == '-h' || a == '--help' }
  puts optparser.help
  exit
end

if options[:target].nil? || options[:registry_key].nil?
  abort(optparser.help)
end

address = options[:target]
registry_key = options[:registry_key]

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock, read_timeout: 60)

client = RubySMB::Client.new(dispatcher, smb1: options[:smbv1], smb2: options[:smbv2], smb3: options[:smbv3], username: options[:username], password: options[:password], domain: options[:domain])
protocol = client.negotiate
status = client.authenticate

puts "#{protocol} : #{status}"

enum_result = client.enum_registry_key(address, registry_key)
puts enum_result

client.disconnect!
