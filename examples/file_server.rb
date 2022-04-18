#!/usr/bin/ruby

require 'bundler/setup'
require 'optparse'
require 'ruby_smb'
require 'ruby_smb/gss/provider/ntlm'

# we just need *a* default encoding to handle the strings from the NTLM messages
Encoding.default_internal = 'UTF-8' if Encoding.default_internal.nil?

options = {
  allow_anonymous: true,
  allow_guests: false,
  domain: nil,
  username: 'RubySMB',
  password: 'password',
  share_name: 'home',
  share_path: '.',
  smbv1: true,
  smbv2: true,
  smbv3: true
}
OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename(__FILE__)} [options]"
  opts.on("--path PATH", "The path to share (default: #{options[:share_path]})") do |path|
    options[:share_path] = path
  end
  opts.on("--share SHARE", "The share name (default: #{options[:share_name]})") do |share|
    options[:share_name] = share
  end
  opts.on("--[no-]anonymous", "Allow anonymous access (default: #{options[:allow_anonymous]})") do |allow_anonymous|
    options[:allow_anonymous] = allow_anonymous
  end
  opts.on("--[no-]smbv1", "Enable or disable SMBv1 (default: #{options[:smbv1] ? 'Enabled' : 'Disabled'})") do |smbv1|
    options[:smbv1] = smbv1
  end
  opts.on("--[no-]smbv2", "Enable or disable SMBv2 (default: #{options[:smbv2] ? 'Enabled' : 'Disabled'})") do |smbv2|
    options[:smbv2] = smbv2
  end
  opts.on("--[no-]smbv3", "Enable or disable SMBv3 (default: #{options[:smbv3] ? 'Enabled' : 'Disabled'})") do |smbv3|
    options[:smbv3] = smbv3
  end
  opts.on("--[no-]guests", "Allow guest accounts (default: #{options[:allow_guests]})") do |allow_guests|
    options[:allow_guests] = allow_guests
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
end.parse!

ntlm_provider = RubySMB::Gss::Provider::NTLM.new(
  allow_anonymous: options[:allow_anonymous],
  allow_guests: options[:allow_guests]
)
ntlm_provider.put_account(options[:username], options[:password], domain: options[:domain])  # password can also be an NTLM hash

server = RubySMB::Server.new(
  gss_provider: ntlm_provider,
  logger: :stdout
)
server.dialects.select! { |dialect| RubySMB::Dialect[dialect].family != RubySMB::Dialect::FAMILY_SMB1 } unless options[:smbv1]
server.dialects.select! { |dialect| RubySMB::Dialect[dialect].family != RubySMB::Dialect::FAMILY_SMB2 } unless options[:smbv2]
server.dialects.select! { |dialect| RubySMB::Dialect[dialect].family != RubySMB::Dialect::FAMILY_SMB3 } unless options[:smbv3]

if server.dialects.empty?
  puts "at least one version must be enabled"
  exit false
end

server.add_share(RubySMB::Server::Share::Provider::Disk.new(options[:share_name], options[:share_path]))
puts "server is running"
server.run do
  puts "received connection"
  true
end

