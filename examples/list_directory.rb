#!/usr/bin/ruby

# This example script is used for testing directory listing functionality
# It will attempt to connect to a specific share and then list all files in a
#  specified directory..
# Example usage: ruby list_directory.rb 192.168.172.138 msfadmin msfadmin TEST_SHARE subdir1
# This will try to connect to \\192.168.172.138\TEST_SHARE with the msfadmin:msfadmin credentials,
# and then list the contents of the directory 'subdir1'

require 'bundler/setup'
require 'ruby_smb'

address  = ARGV[0]
username = ARGV[1]
password = ARGV[2]
share    = ARGV[3]
dir      = ARGV[4]
path     = "\\\\#{address}\\#{share}"

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock)

client = RubySMB::Client.new(dispatcher, smb1: true, smb2: true, username: username, password: password)
protocol = client.negotiate
status  = client.authenticate

puts "#{protocol} : #{status}"

begin
  tree = client.tree_connect(path)
  puts "Connected to #{path} successfully!"
rescue Exception => e
  puts "Failed to connect to #{path}: #{e.message}"
end

files = tree.list(directory: dir)

require 'pry'
binding.pry


