#!/usr/bin/ruby

# This example script is used for launching a powershell command as a service on a host.
# It will attempt to connect to a host and create a new service to launch the command using powershell.exe.
# Example usage: ruby pwsh_service.rb 192.168.172.138 msfadmin msfadmin "echo test > C:\\Users\\User\\Desktop\\test.txt"
# This will try to connect to \\192.168.172.138 with the msfadmin:msfadmin credentials and create a new service to run the powershell command.

require 'bundler/setup'
require 'ruby_smb'

address      = ARGV[0]
username     = ARGV[1]
password     = ARGV[2]
command      = ARGV[3]
smb_versions = ARGV[4]&.split(',') || ['1','2','3']

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock, read_timeout: 60)

client = RubySMB::Client.new(dispatcher, smb1: smb_versions.include?('1'), smb2: smb_versions.include?('2'), smb3: smb_versions.include?('3'), username: username, password: password)
protocol = client.negotiate
status = client.authenticate

puts "#{protocol} : #{status}"

tree = client.tree_connect("\\\\#{address}\\IPC$")
svcctl = tree.open_file(filename: 'svcctl', write: true, read: true)

puts('Binding to \\svcctl...')
svcctl.bind(endpoint: RubySMB::Dcerpc::Svcctl)
puts('Bound to \\svcctl')

puts('Opening Service Control Manager')
scm_handle = svcctl.open_sc_manager_w(address)

service_name = (1..8).map { (('a'..'z').to_a + ('A'..'Z').to_a)[rand(26*2)] }.join
display_name = (1..8).map { (('a'..'z').to_a + ('A'..'Z').to_a)[rand(26*2)] }.join
binary_path_name = "%COMSPEC% /b /c start /b /min powershell.exe -nop -win hid -noni -en #{[command.encode("UTF-16LE")].pack("m0")}"
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
