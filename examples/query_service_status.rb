#!/usr/bin/ruby

# This example script is used for testing remote service status and start type query.
# It will attempt to connect to a host and query the status and start type of the provided service.
# Example usage: ruby query_service_status.rb --username msfadmin --password msfadmin 192.168.172.138 "RemoteRegistry"
# This will try to connect to \\192.168.172.138 with the msfadmin:msfadmin credentialas and get the status and start type of the "RemoteRegistry" service.

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
  service: nil
}
options[:service] = args.pop
options[:target] = args.pop
optparser = OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename(__FILE__)} [options] target service"
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

if [options[:target], options[:service]].any? { |a| a == '-h' || a == '--help' }
  puts optparser.help
  exit
end

if options[:target].nil? || options[:service].nil?
  abort(optparser.help)
end

address = options[:target]
service = options[:service]

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock, read_timeout: 60)

client = RubySMB::Client.new(dispatcher, smb1: options[:smbv1], smb2: options[:smbv2], smb3: options[:smbv3], username: options[:username], password: options[:password], domain: options[:domain])
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

svc_handle = svcctl.open_service_w(scm_handle, service)
svc_status = svcctl.query_service_status(svc_handle)

puts
case svc_status.dw_current_state
when RubySMB::Dcerpc::Svcctl::SERVICE_RUNNING
  puts("Service #{service} is running")
when RubySMB::Dcerpc::Svcctl::SERVICE_STOPPED
  puts("Service #{service} is in stopped state")
end
puts

svc_config = svcctl.query_service_config(svc_handle)

service_type = 'Service type: '
case svc_config.dw_service_type
when RubySMB::Dcerpc::Svcctl::SERVICE_KERNEL_DRIVER
  service_type << 'Driver service'
when RubySMB::Dcerpc::Svcctl::SERVICE_FILE_SYSTEM_DRIVER
  service_type << 'File system driver service'
when RubySMB::Dcerpc::Svcctl::SERVICE_WIN32_OWN_PROCESS
  service_type << 'Service that runs in its own process'
when RubySMB::Dcerpc::Svcctl::SERVICE_WIN32_SHARE_PROCESS
  service_type << 'Service that shares a process with other services'
end

start_type = 'Service start type: '
case svc_config.dw_start_type
when RubySMB::Dcerpc::Svcctl::SERVICE_DISABLED
  start_type << 'Service is disabled'
when RubySMB::Dcerpc::Svcctl::SERVICE_BOOT_START, RubySMB::Dcerpc::Svcctl::SERVICE_SYSTEM_START
  start_type << 'Service starts when the system boots up (driver)'
when RubySMB::Dcerpc::Svcctl::SERVICE_AUTO_START
  start_type << 'Service starts automatically during system startup'
when RubySMB::Dcerpc::Svcctl::SERVICE_DEMAND_START
  start_type << 'Service starts manually'
end

error_control = 'Error control: '
case svc_config.dw_error_control
when RubySMB::Dcerpc::Svcctl::SERVICE_ERROR_IGNORE
  error_control << 'SERVICE_ERROR_IGNORE'
when RubySMB::Dcerpc::Svcctl::SERVICE_ERROR_NORMAL
  error_control << 'SERVICE_ERROR_NORMAL'
when RubySMB::Dcerpc::Svcctl::SERVICE_ERROR_SEVERE
  error_control << 'SERVICE_ERROR_SEVERE'
when RubySMB::Dcerpc::Svcctl::SERVICE_ERROR_CRITICAL
  error_control << 'SERVICE_ERROR_CRITICAL'
end

puts service_type
puts start_type
puts error_control
puts "Binary path: #{svc_config.lp_binary_path_name.to_s.encode('utf-8')}"
puts "Load ordering service group: #{svc_config.lp_load_order_group.to_s.encode('utf-8')}"
puts "Service group tag ID: #{svc_config.dw_tag_id.to_s.encode('utf-8')}"
puts "Dependencies: #{svc_config.lp_dependencies.to_s.encode('utf-8')}"
puts "Service start name: #{svc_config.lp_service_start_name.to_s.encode('utf-8')}"


if svcctl
  svcctl.close_service_handle(svc_handle) if svc_handle
  svcctl.close_service_handle(scm_handle) if scm_handle
  svcctl.close
end
client.disconnect!
