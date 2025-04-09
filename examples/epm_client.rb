#!/usr/bin/ruby

require 'bundler/setup'
require 'ruby_smb'

require 'optparse'
require 'pp'

options = {
  major_version: 1,
  minor_version: 0,
  max_towers: 1,
}

parser = OptionParser.new do |opts|
  opts.banner = "Usage: script.rb [options] TARGET PROTOCOL UUID"

  opts.on("--major-version N", Integer, "Specify major version number (default: #{options[:major_version]})") do |v|
    options[:major_version] = v
  end

  opts.on("--minor-version N", Integer, "Specify minor version number ((default: #{options[:minor_version]})") do |v|
    options[:minor_version] = v
  end

  opts.on("--max-towers N", Integer, "Set the maximum number of towers (default: #{options[:max_towers]})") do |v|
    options[:max_towers] = v
  end

  opts.on("-h", "--help", "Prints this help") do
    puts opts
    exit
  end
end

# Parse and extract positional arguments
begin
  parser.order!(ARGV)
  if ARGV.size != 3
    raise OptionParser::MissingArgument, "TARGET, PROTOCOL, and UUID are required"
  end

  options[:target], options[:protocol], options[:uuid] = ARGV
rescue OptionParser::ParseError => e
  puts e.message
  puts parser
  exit 1
end

dcerpc_client = RubySMB::Dcerpc::Client.new(options[:target], RubySMB::Dcerpc::Epm)
dcerpc_client.connect
dcerpc_client.bind
dcerpc_client.ept_map(
  uuid: options[:uuid],
  maj_ver: options[:major_version],
  min_ver: options[:minor_version],
  protocol: options[:protocol].to_sym,
  max_towers: options[:max_towers]
).each do |tower|
  puts "Tower: #{tower[:endpoint]}"
  tower.each do |key, value|
    next if key == :endpoint
    puts "  #{key}: #{value}"
  end
end