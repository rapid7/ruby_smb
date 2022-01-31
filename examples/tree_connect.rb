#!/usr/bin/ruby

# This example script is used for testing TreeConnect functionality
# It will attempt to connect to a specific share and then disconnect.
# Example usage: ruby tree_connect.rb 192.168.172.138 msfadmin msfadmin TEST_SHARE
# This will try to connect to \\192.168.172.138\TEST_SHARE with the msfadmin:msfadmin credentials

require 'bundler/setup'
require 'optparse'
require 'ruby_smb'

args = ARGV.dup
options = {
  domain: '.',
  username: '',
  password: '',
  share: nil,
  smbv1: true,
  smbv2: true,
  smbv3: true,
  target: nil
}
options[:share] = args.pop
options[:target ] = args.pop
optparser = OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename(__FILE__)} [options] target share"
  opts.on("--[no-]smbv1", "Enabled or disable SMBv1 (default: #{options[:smbv1] ? 'Enabled' : 'Disabled'})") do |smbv1|
    options[:smbv1] = smbv1
  end
  opts.on("--[no-]smbv2", "Enabled or disable SMBv2 (default: #{options[:smbv2] ? 'Enabled' : 'Disabled'})") do |smbv2|
    options[:smbv2] = smbv2
  end
  opts.on("--[no-]smbv3", "Enabled or disable SMBv3 (default: #{options[:smbv3] ? 'Enabled' : 'Disabled'})") do |smbv3|
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

if options[:target].nil? || options[:share].nil?
  abort(optparser.help)
end

path = "\\\\#{options[:target]}\\#{options[:share]}"

sock = TCPSocket.new options[:target], 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock)

client = RubySMB::Client.new(dispatcher, smb1: options[:smbv1], smb2: options[:smbv2], smb3: options[:smbv3], username: options[:username], password: options[:password], domain: options[:domain])
protocol = client.negotiate
status = client.authenticate

puts "#{protocol} : #{status}"

begin
  tree = client.tree_connect(path)
  puts "Connected to #{path} successfully!"
  tree.disconnect!
rescue StandardError => e
  puts "Failed to connect to #{path}: #{e.message}"
end
