#!/usr/bin/ruby

# This example script is used for testing DCERPC WKST requests.
# It will attempt to retrieve configuration information of a remote computer/server.
# Example usage: ruby get_computer_info.rb --username msfadmin --password msfadmin 192.168.172.138

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

address = options[:target]

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock, read_timeout: 60)

client = RubySMB::Client.new(dispatcher, smb1: options[:smbv1], smb2: options[:smbv2], smb3: options[:smbv3], username: options[:username], password: options[:password], domain: options[:domain])
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
