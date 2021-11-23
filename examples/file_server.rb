#!/usr/bin/ruby

require 'bundler/setup'
require 'optparse'
require 'ruby_smb'
require 'ruby_smb/gss/provider/ntlm'

options = {
  allow_anonymous: true,
  domain: nil,
  username: 'RubySMB',
  password: 'password',
  share_name: 'home',
  share_path: '.'
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

ntlm_provider = RubySMB::Gss::Provider::NTLM.new(allow_anonymous: options[:allow_anonymous])
ntlm_provider.put_account(options[:username], options[:password], domain: options[:domain])  # password can also be an NTLM hash

server = RubySMB::Server.new(
  gss_provider: ntlm_provider,
  logger: :stdout
)
server.add_share(RubySMB::Server::Share::Provider::Disk.new(options[:share_name], options[:share_path]))
puts "server is running"
server.run do
  puts "received connection"
  true
end

