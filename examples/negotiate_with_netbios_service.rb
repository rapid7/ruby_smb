#!/usr/bin/ruby

# This script is for testing the NetBIOS Session Service Request on port 139/tcp.
# Example usage: ruby negotiate_with_netbios_service.rb 192.168.172.138 NBNAME
# This will connect to 192.168.172.138 (139/TCP) and request a NetBIOS session with NBNAME as the called name.
# If successful, a SMB negotiation is performed using this NetBIOS session.
# The default *SMBSERVER name is used if the NetBIOS name is not provided.

require 'bundler/setup'
require 'optparse'
require 'ruby_smb'

def run_negotiation(address, smb1, smb2, smb3, netbios_name)
  sock = TCPSocket.new address, 139
  dispatcher = RubySMB::Dispatcher::Socket.new(sock)

  client = RubySMB::Client.new(dispatcher, smb1: smb1, smb2: smb2, smb3: smb3, username: '', password: '')
  begin
    client.session_request(netbios_name)
  rescue RubySMB::Error::NetBiosSessionService => e
    puts "NetBIOS Session refused with #{netbios_name}: #{e.message}"
    return
  end
  puts "NetBIOS Session granted with #{netbios_name}, negotiating..."
  smb_version = client.negotiate
  puts "#{smb_version} successfully negotiated."
end

args = ARGV.dup
options = {
  smbv1: true,
  smbv2: true,
  smbv3: true,
  netbios_name: '*SMBSERVER',
  target: nil
}
options[:target] = args.pop
optparser = OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename(__FILE__)} [options] target"
  opts.on("--[no-]smbv1", "Enable or disable SMBv1 (default: #{options[:smbv1] ? 'Enabled' : 'Disabled'})") do |smbv1|
    options[:smbv1] = smbv1
  end
  opts.on("--[no-]smbv2", "Enable or disable SMBv2 (default: #{options[:smbv2] ? 'Enabled' : 'Disabled'})") do |smbv2|
    options[:smbv2] = smbv2
  end
  opts.on("--[no-]smbv3", "Enable or disable SMBv3 (default: #{options[:smbv3] ? 'Enabled' : 'Disabled'})") do |smbv3|
    options[:smbv3] = smbv3
  end
  opts.on("--netbios-name NAME", "The NetBIOS called name (default: #{options[:netbios_name]})") do |name|
    options[:netbios_name] = name
  end
end
optparser.parse!(args)

if options[:target] == '-h' || options[:target] == '--help'
  puts optparser.help
  exit
end

if options[:target].nil?
  abort(optparser.help)
end

# (smb1, smb2, smb3) combinations to exercise — filtered by the user's
# --[no-]smbv{1,2,3} flags so any combo requiring a disabled version
# is skipped.
combinations = [
  [true,  true,  true],   # SMB1, SMB2 and SMB3 enabled
  [true,  true,  false],  # SMB1 and SMB2 enabled
  [true,  false, false],  # only SMB1 enabled
  [false, true,  false],  # only SMB2 enabled
  [false, false, true]    # only SMB3 enabled
]

combinations.each do |smb1, smb2, smb3|
  next if smb1 && !options[:smbv1]
  next if smb2 && !options[:smbv2]
  next if smb3 && !options[:smbv3]
  run_negotiation(options[:target], smb1, smb2, smb3, options[:netbios_name])
end
