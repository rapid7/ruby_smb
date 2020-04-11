#!/usr/bin/ruby

# This example script is used for testing the reading of a file.
# It will attempt to connect to a specific share and then read a specified file.
# Example usage: ruby read_file.rb 192.168.172.138 msfadmin msfadmin TEST_SHARE short.txt
# This will try to connect to \\192.168.172.138\TEST_SHARE with the msfadmin:msfadmin credentials
# and read the file short.txt

require 'bundler/setup'
require 'ruby_smb'

address  = ARGV[0]
username = ARGV[1]
password = ARGV[2]
share    = ARGV[3]
file     = ARGV[4]
path     = "\\\\#{address}\\#{share}"

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock)

# To require encryption on the server, run this in an elevated Powershell:
# C:\> Set-SmbServerConfiguration -EncryptData $true

# To enable per-share encrytion on the server, run this in an elevated Powershell:
# C:\ Set-SmbServerConfiguration -EncryptData $false
# C:\ Set-SmbShare -Name <share name> -EncryptData 1

# When encryption is not required by the server, the client can still use
# encryption. Set this to true to force encryption:
force_encryption = false

client = RubySMB::Client.new(dispatcher, smb1: false, smb2: false, smb3: true, username: username, password: password, force_encryption: force_encryption)
protocol = client.negotiate
status = client.authenticate

begin
  tree = client.tree_connect(path)
rescue StandardError => e
  puts "Failed to connect to #{path}: #{e.message}"
end

file = tree.open_file(filename: file)

data = file.read
puts data
file.close
