#!/usr/bin/env ruby

require 'bundler/setup'

require 'ruby_smb'

host = ARGV.first
if host.nil?
  $stderr.puts("Usage: #{$0} <ip address>")
  exit 1
end

d = RubySMB::Dispatcher::Socket.connect(host, 445)

c = RubySMB::Smb2::Client.new(dispatcher: d, username: "msfadmin", password: "msfadmin")

c.negotiate
c.authenticate
tree = c.tree_connect("\\\\#{host}\\C$")

file = tree.create("Users\\Public\\foo.txt")

puts file.read
