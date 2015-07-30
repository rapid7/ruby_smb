#!/usr/bin/env ruby

require 'bundler/setup'

require 'optparse'
require 'ruby_smb'

username = "msfadmin"
password = "msfadmin"

op = OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} <HOST> [options]"
  opts.on("-U",
          "--user=USER[%password]",
  ) do |user|
    username, password = user.split("%", 2)
  end
end

host = ARGV.first
if host.nil?
  puts op
  exit 1
end

op.parse!(ARGV)

d = RubySMB::Dispatcher::Socket.connect(host, 445)
puts "Connected"

c = RubySMB::SMB2::Client.new(dispatcher: d, username: username, password: password)

c.negotiate
result = c.authenticate
unless 0 == result
  puts "Error authenticating: #{result}"
  exit 2
end

tree = c.tree_connect("\\\\#{host}\\C$")

written = "write works\n"
file = tree.create("smb2-delete-me.txt", "w")
file.write(written)
file.close

file = tree.create("smb2-delete-me.txt", "r")
data = file.read
file.close
if data == written
  puts "Read and write work"
else
  puts "Expected #{written.inspect}"
  puts "Read #{data.inspect}"
end
tree.delete("smb2-delete-me.txt")

# "r" so we don't create non-existing (which is default, "r+")
file = tree.create("smb2-delete-me.txt", "r")

case file.create_response.nt_status
when 0
  puts "Error deleting, file still exists"
  exit 1
when 0xC000_0034 # STATUS_OBJECT_NAME_NOT_FOUND
  puts "Deleting works"
end
