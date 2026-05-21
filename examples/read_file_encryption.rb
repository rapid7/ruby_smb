#!/usr/bin/ruby

# This example script is used for testing the reading of a file with SMBv3 encryption.
# It will attempt to connect to a specific share and then read a specified file.
# Example usage: ruby read_file_encryption.rb --username msfadmin --password msfadmin 192.168.172.138 TEST_SHARE short.txt
# This will try to connect to \\192.168.172.138\TEST_SHARE with the msfadmin:msfadmin credentials
# and read the file short.txt

# To require encryption on the server, run this in an elevated Powershell:
# C:\> Set-SmbServerConfiguration -EncryptData $true

# To enable per-share encryption on the server, run this in an elevated Powershell:
# C:\ Set-SmbServerConfiguration -EncryptData $false
# C:\ Set-SmbShare -Name <share name> -EncryptData 1

# For this encryption to work, it has to be SMBv3. By default, SMBv1 and SMBv2
# are disabled here so the server will negotiate SMBv3 if it supports it.

require 'bundler/setup'
require 'optparse'
require 'ruby_smb'

args = ARGV.dup
options = {
  domain: '.',
  username: '',
  password: '',
  smbv1: false,
  smbv2: false,
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

# By default, the client uses encryption even if it is not required by the server. Disable this by setting always_encrypt to false
client_opts = {
  smb1: options[:smbv1],
  smb2: options[:smbv2],
  smb3: options[:smbv3],
  username: options[:username],
  password: options[:password],
  domain: options[:domain]
}
#client_opts[:always_encrypt] = false

client = RubySMB::Client.new(dispatcher, **client_opts)
protocol = client.negotiate
status = client.authenticate

begin
  tree = client.tree_connect(path)
rescue StandardError => e
  puts "Failed to connect to #{path}: #{e.message}"
end

file = tree.open_file(filename: options[:file])

data = file.read
puts data
file.close
