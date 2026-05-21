#!/usr/bin/ruby

# This example script is used for testing directory listing functionality
# It will attempt to connect to a specific share and then list all files in a
#  specified directory.
# Example usage: ruby list_directory.rb --username msfadmin --password msfadmin 192.168.172.138 TEST_SHARE subdir1
# This will try to connect to \\192.168.172.138\TEST_SHARE with the msfadmin:msfadmin credentials,
# and then list the contents of the directory 'subdir1'

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
  directory: nil
}
options[:directory] = args.pop
options[:share] = args.pop
options[:target] = args.pop
optparser = OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename(__FILE__)} [options] target share directory"
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

if [options[:target], options[:share], options[:directory]].any? { |a| a == '-h' || a == '--help' }
  puts optparser.help
  exit
end

if options[:target].nil? || options[:share].nil? || options[:directory].nil?
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

files = tree.list(directory: options[:directory])

files.each do |file|
  create_time = file.create_time.to_datetime.to_s
  access_time = file.last_access.to_datetime.to_s
  change_time = file.last_change.to_datetime.to_s
  file_name   = file.file_name.encode('UTF-8')

  puts "FILE: #{file_name}\n\tSIZE(BYTES):#{file.end_of_file}\n\tSIZE_ON_DISK(BYTES):#{file.allocation_size}\n\tCREATED:#{create_time}\n\tACCESSED:#{access_time}\n\tCHANGED:#{change_time}\n\n"
end
