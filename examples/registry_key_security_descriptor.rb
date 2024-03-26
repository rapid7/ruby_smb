#!/usr/bin/ruby

# This example script is used for testing the Winreg registry key security descriptor functionalities.
# It will attempt to connect to a host and reads (or writes) the security descriptor of a specified registry key.
#
# Example usage:
# - read:
# ruby examples/read_registry_key_security.rb --username msfadmin --password msfadmin -i 7 -o r 192.168.172.138 'HKLM\SECURITY\Policy\PolEKList'
# This will try to connect to \\192.168.172.138 with the msfadmin:msfadmin
# credentialas and read the security descriptor of the
# `HKLM\SECURITY\Policy\PolEKList` registry key with the security information 7
# (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
# DACL_SECURITY_INFORMATION).
#
# - write:
# ruby examples/read_registry_key_security.rb --username msfadmin --password msfadmin -i 4 --sd 01000480000000000000000000000000140000000200340002000000000214003f000f00010100000000000512000000000218000000060001020000000000052000000020020000 -o w 192.168.172.138 'HKLM\SECURITY\Policy\PolEKList'
# This will try to connect to \\192.168.172.138 with the msfadmin:msfadmin
# credentialas and write the given security descriptor to the
# `HKLM\SECURITY\Policy\PolEKList` registry key with the security information 4
# (DACL_SECURITY_INFORMATION).

require 'bundler/setup'
require 'optparse'
require 'ruby_smb'

OPERATIONS = %w{read write}
OPERATION_ALIASES = { "r" => "read", "w" => "write" }

args = ARGV.dup
options = {
  domain: '.',
  username: '',
  password: '',
  smbv1: true,
  smbv2: true,
  smbv3: true,
  target: nil,
  key: nil,
  operation: 'read',
  info: RubySMB::Field::SecurityDescriptor::OWNER_SECURITY_INFORMATION | RubySMB::Field::SecurityDescriptor::GROUP_SECURITY_INFORMATION | RubySMB::Field::SecurityDescriptor::DACL_SECURITY_INFORMATION,
  sd: nil
}
options[:key] = args.pop
options[:target ] = args.pop
optparser = OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename(__FILE__)} [options] target reg_key"
  opts.on('--[no-]smbv1', "Enable or disable SMBv1 (default: #{options[:smbv1] ? 'Enabled' : 'Disabled'})") do |smbv1|
    options[:smbv1] = smbv1
  end
  opts.on('--[no-]smbv2', "Enable or disable SMBv2 (default: #{options[:smbv2] ? 'Enabled' : 'Disabled'})") do |smbv2|
    options[:smbv2] = smbv2
  end
  opts.on('--[no-]smbv3', "Enable or disable SMBv3 (default: #{options[:smbv3] ? 'Enabled' : 'Disabled'})") do |smbv3|
    options[:smbv3] = smbv3
  end
  opts.on('-u', '--username [USERNAME]', "The account's username (default: #{options[:username]})") do |username|
    if username.include?('\\')
      options[:domain], options[:username] = username.split('\\', 2)
    else
      options[:username] = username
    end
  end
  opts.on('-p', '--password [PASSWORD]', "The account's password (default: #{options[:password]})") do |password|
    options[:password] = password
  end
  operation_list = (OPERATION_ALIASES.keys + OPERATIONS).join(', ')
  opts.on('-o', '--operation OPERATION', OPERATIONS, OPERATION_ALIASES, "The operation to perform on the registry key (default: #{options[:operation]})", "(#{operation_list})") do |operation|
    options[:operation] = operation
  end
  opts.on('-i', '--info [SECURITY INFORMATION]', Integer, "The security information value (default: #{options[:info]})") do |password|
    options[:info] = password
  end
  opts.on('-s', '--sd [SECURITY DESCRIPTOR]', "The security descriptor to write as an hex string") do |sd|
    options[:sd] = sd
  end
end
optparser.parse!(args)

if options[:target].nil? || options[:key].nil?
  abort(optparser.help)
end

sock = TCPSocket.new options[:target], 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock)

client = RubySMB::Client.new(dispatcher, smb1: options[:smbv1], smb2: options[:smbv2], smb3: options[:smbv3], username: options[:username], password: options[:password], domain: options[:domain])
protocol = client.negotiate
status = client.authenticate

puts "#{protocol}: #{status}"

case options[:operation]
when 'read', 'r'
  puts "Read registry key #{options[:key]} security descriptor with security information #{options[:info]}"
  security_descriptor = client.get_key_security_descriptor(options[:target], options[:key], options[:info])
  puts "Security descriptor: #{security_descriptor.b.bytes.map {|c| "%02x" % c.ord}.join}"
when 'write', 'w'
  unless options[:sd] && !options[:sd].empty?
    puts "Security descriptor missing"
    abort(optparser.help)
  end
  puts "Write security descriptor #{options[:sd]} to registry key #{options[:key]} with security information #{options[:info]}"
  sd = options[:sd].chars.each_slice(2).map {|c| c.join.to_i(16).chr}.join
  status = client.set_key_security_descriptor(options[:target], options[:key], sd, options[:info])
  puts "Success!"
end

client.disconnect!

