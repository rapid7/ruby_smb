#!/usr/bin/ruby

#
# This script is for testing the Protocol Negotiation in the library
# without any other parts.

require 'bundler/setup'
require 'optparse'
require 'ruby_smb'

def run_negotiation(address, smb1, smb2, smb3)
  # Create our socket and add it to the dispatcher
  sock = TCPSocket.new address, 445
  dispatcher = RubySMB::Dispatcher::Socket.new(sock)

  client = RubySMB::Client.new(dispatcher, smb1: smb1, smb2: smb2, smb3: smb3, username: '', password: '')
  client.negotiate
end

args = ARGV.dup
options = {
  smbv1: true,
  smbv2: true,
  smbv3: true,
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
  [true,  false, false], # only SMB1
  [false, true,  false], # only SMB2
  [false, false, true],  # only SMB3
  [true,  true,  false], # SMB1 and SMB2
  [false, true,  true],  # SMB2 and SMB3
  [true,  false, true],  # SMB1 and SMB3
  [true,  true,  true]   # SMB1, SMB2 and SMB3
]

combinations.each do |smb1, smb2, smb3|
  next if smb1 && !options[:smbv1]
  next if smb2 && !options[:smbv2]
  next if smb3 && !options[:smbv3]

  enabled = []
  enabled << 'SMB1' if smb1
  enabled << 'SMB2' if smb2
  enabled << 'SMB3' if smb3
  puts "Negotiate with #{enabled.join(', ')} enabled..."
  begin
    puts "  Negotiated version: #{run_negotiation(options[:target], smb1, smb2, smb3)}"
  rescue RubySMB::Error::RubySMBError => e
    puts "Error: #{e.message}"
  end
end
