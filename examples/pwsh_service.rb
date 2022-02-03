#!/usr/bin/ruby

# This example script is used for launching a powershell command as a service on a host.
# It will attempt to connect to a host and create a new service to launch the command using powershell.exe.
# Example usage: ruby pwsh_service.rb --username msfadmin --password msfadmin 192.168.172.138 "echo test > C:\\Users\\User\\Desktop\\test.txt"
# This will try to connect to \\192.168.172.138 with the msfadmin:msfadmin credentials and create a new service to run the powershell command.

def random_string(length)
  return (1..length).map { (('a'..'z').to_a + ('A'..'Z').to_a)[rand(26*2)] }.join
end

require 'bundler/setup'
require 'optparse'
require 'ruby_smb'

args = ARGV.dup
options = {
  domain: '.',
  username: '',
  password: '',
  command: nil,
  smbv1: true,
  smbv2: true,
  smbv3: true,
  target: nil
}
options[:command] = args.pop
options[:target] = args.pop
optparser = OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename(__FILE__)} [options] target command"
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

if options[:target].nil? || options[:command].nil?
  abort(optparser.help)
end

sock = TCPSocket.new options[:target], 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock, read_timeout: 60)

client = RubySMB::Client.new(dispatcher, smb1: options[:smbv1], smb2: options[:smbv2], smb3: options[:smbv3], username: options[:username], password: options[:password], domain: options[:domain])
protocol = client.negotiate
status = client.authenticate

puts "#{protocol} : #{status}"

tree = client.tree_connect("\\\\#{options[:target]}\\IPC$")
svcctl = tree.open_file(filename: 'svcctl', write: true, read: true)

puts('Binding to \\svcctl...')
svcctl.bind(endpoint: RubySMB::Dcerpc::Svcctl)
puts('Bound to \\svcctl')

puts('Opening Service Control Manager')
scm_handle = svcctl.open_sc_manager_w(options[:target])

service_name = random_string(8)
display_name = random_string(8)
binary_path_name = "%COMSPEC% /b /c start /b /min powershell.exe -nop -win hid -noni -en #{[options[:command].encode("UTF-16LE")].pack("m0")}"
puts "Full Command: #{binary_path_name}"
svc_handle = svcctl.create_service_w(scm_handle, service_name, display_name, binary_path_name)

puts('Created new service')

svcctl.close_service_handle(svc_handle)

puts('Opening the service')

svc_handle = svcctl.open_service_w(scm_handle, service_name)

puts('Starting the service')

begin
  svcctl.start_service_w(svc_handle)
rescue RubySMB::Dcerpc::Error::SvcctlError
end

puts('Deleting the service')

svcctl.delete_service(svc_handle)

puts('Closing Service Control Manager')

svcctl.close_service_handle(scm_handle)

puts('Done')

client.disconnect!
