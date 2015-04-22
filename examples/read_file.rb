#!/usr/bin/env ruby

$:.push File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'smb2'

host = ARGV.first
if host.nil?
  $stderr.puts("Usage: #{$0} <ip address>")
  exit 1
end

d = Smb2::Dispatcher::Socket.connect(host, 445)

c = Smb2::Client.new(dispatcher: d, username:"msfadmin", password:"msfadmin")

c.negotiate
c.authenticate
tree = c.tree_connect("\\\\#{host}\\Users")

file = tree.create("public\\foo.txt".encode('utf-16le'))

puts file.read
