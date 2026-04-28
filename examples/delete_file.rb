#!/usr/bin/ruby

# This example script is used for testing the deleting of a file.
# It will attempt to connect to a specific share and then delete a specified file.
# Example usage: ruby delete_file.rb --username msfadmin --password msfadmin 192.168.172.138 TEST_SHARE short.txt
# This will try to connect to \\192.168.172.138\TEST_SHARE with the msfadmin:msfadmin credentials
# and delete the file short.txt

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
  share: nil,
  file: nil
}
options[:file] = args.pop
options[:share] = args.pop
options[:target] = args.pop
optparser = OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename(__FILE__)} [options] target share file"
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

if [options[:target], options[:share], options[:file]].any? { |a| a == '-h' || a == '--help' }
  puts optparser.help
  exit
end

if options[:target].nil? || options[:share].nil? || options[:file].nil?
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
rescue StandardError => e
  puts "Failed to connect to #{path}: #{e.message}"
end

file = tree.open_file(filename: options[:file], delete: true)

data = file.delete
puts data
file.close
