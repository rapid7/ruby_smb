#!/usr/bin/ruby

require 'bundler/setup'
require 'optparse'
require 'ruby_smb'

# we just need *a* default encoding to handle the strings from the NTLM messages
Encoding.default_internal = 'UTF-8' if Encoding.default_internal.nil?

options = RubySMB::Server::Cli.parse(defaults: { share_path: '.' }) do |options, parser|
  parser.banner = "Usage: #{File.basename(__FILE__)} [options]"

  parser.on("--path PATH", "The path to share (default: #{options[:share_path]})") do |path|
    options[:share_path] = path
  end
end

server = RubySMB::Server::Cli.build(options)
server.add_share(RubySMB::Server::Share::Provider::Disk.new(options[:share_name], options[:share_path]))

RubySMB::Server::Cli.run(server)
