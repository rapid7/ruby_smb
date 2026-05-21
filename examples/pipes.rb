#!/usr/bin/ruby

#
# Example script for connecting to a named pipe and performing a peek operation.
# This is used to demonstrate pipe operations.
#
# Usage: ruby pipes.rb --username USER --password PASS ADDRESS PIPENAME
#

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
  pipename: nil
}
options[:pipename] = args.pop
options[:target] = args.pop
optparser = OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename(__FILE__)} [options] target pipename"
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

if [options[:target], options[:pipename]].any? { |a| a == '-h' || a == '--help' }
  puts optparser.help
  exit
end

if options[:target].nil? || options[:pipename].nil?
  abort(optparser.help)
end

address = options[:target]
pipename = options[:pipename]

sock = TCPSocket.new(address, 445)
dispatcher = RubySMB::Dispatcher::Socket.new(sock)

client = RubySMB::Client.new(dispatcher, smb1: options[:smbv1], smb2: options[:smbv2], smb3: options[:smbv3], username: options[:username], password: options[:password], domain: options[:domain])
smbver = client.negotiate

if smbver == 'SMB1'
  puts "ServerMaxBuffer: #{client.server_max_buffer_size}"
else
  puts "ServerMaxRead:   #{client.server_max_read_size}"
  puts "ServerMaxWrite:  #{client.server_max_write_size}"
  puts "ServerMaxTrans:  #{client.server_max_transact_size}"
end

client.authenticate
client.tree_connect("\\\\#{address}\\IPC$")
client.create_pipe(pipename)
pipe = client.last_file

puts "Available:       #{pipe.peek_available}"
puts "PipeState:       #{pipe.peek_state}" # 3 == OK
puts "IsConnected:     #{pipe.is_connected?}"

pipe.close
puts "IsConnected:     #{pipe.is_connected?}"
client.tree_connects[-1].disconnect!
client.disconnect!
