#!/usr/bin/ruby

# This example script is used for testing NetShareEnumAll functionality
# It will attempt to connect to a host and enumerate shares.
# Example usage: ruby net_share_enum_all.rb 192.168.172.138 msfadmin msfadmin
# This will try to connect to \\192.168.172.138 with the msfadmin:msfadmin credentials

require 'bundler/setup'
require 'ruby_smb'

address  = ARGV[0]
username = ARGV[1]
password = ARGV[2]
path     = "\\\\#{address}\\IPC$"

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock)

client = RubySMB::Client.new(dispatcher, smb1: false, smb2: true, username: username, password: password)

protocol = client.negotiate
status = client.authenticate

puts "#{protocol} : #{status}"

tree = client.tree_connect(path)
file = tree.open_file(filename: "srvsvc", write: true, read: true, disposition: RubySMB::Dispositions::FILE_OPEN_IF)
shares = client.net_share_enum_all(file)
puts shares

file.close
#client.wipe_state!