#!/usr/bin/ruby

require 'bundler/setup'
require 'optparse'
require 'ruby_smb'

# we just need *a* default encoding to handle the strings from the NTLM messages
Encoding.default_internal = 'UTF-8' if Encoding.default_internal.nil?

# see: https://en.wikipedia.org/wiki/Magic_8-ball#Possible_answers
MAGIC_8_BALL_ANSWERS = [
  'It is certain.',
  'It is decidedly so.',
  'Without a doubt.',
  'Yes definitely.',
  'You may rely on it.',
  'As I see it, yes.',
  'Most likely.',
  'Outlook good.',
  'Yes.',
  'Signs point to yes.',
  'Reply hazy, try again.',
  'Ask again later.',
  'Better not tell you now.',
  'Cannot predict now.',
  'Concentrate and ask again.',
  'Don\'t count on it.',
  'My reply is no.',
  'My sources say no.',
  'Outlook not so good.',
  'Very doubtful'
]

options = RubySMB::Server::Cli.parse! do |options, parser|
  parser.banner = "Usage: #{File.basename(__FILE__)} [options]"

  parser.on("--virtual-content CONTENT", "The virtual share contents") do |virtual_content|
    options[:virtual_content] = virtual_content
  end

  parser.on("--virtual-name NAME", "The virtual share file name") do |virtual_name|
    options[:virtual_name] = virtual_name
  end

  parser.on("--virtual-type TYPE", "The virtual share type") do |virtual_type|
    options[:virtual_type] = virtual_type
  end
end

server = RubySMB::Server::Cli.build(options)
virtual_disk = RubySMB::Server::Share::Provider::VirtualDisk.new(options[:share_name])

# greeting is a static text file
virtual_disk.add_static_file('greeting', 'Hello World!')

# self is this example file, it's read when it's added and its #stat object is copied over
virtual_disk.add_static_file('self/static', File.open(__FILE__))

# self is this example file, it's mapped in using a real Pathname object
virtual_disk.add_mapped_file('self/mapped', Pathname.new(File.expand_path(__FILE__)))

# magic_8_ball is a dynamic file that is generated each time it is open
virtual_disk.add_dynamic_file('magic_8_ball') do
  MAGIC_8_BALL_ANSWERS.sample
end

if options[:virtual_content] && options[:virtual_name] && options[:virtual_type]
  case options[:virtual_type].downcase
  when 'static'
    # for static, content is left as is
    virtual_disk.add_static_file(options[:virtual_name], options[:virtual_content])
  when 'mapped'
    # for mapped, content is a file path
    virtual_disk.add_mapped_file(options[:virtual_name], Pathname.new(File.expand_path(options[:virtual_content])))
  when 'dynamic'
    # for dynamic, content is a file path
    virtual_disk.add_dynamic_file(options[:virtual_name]) do
      File.read(options[:virtual_content])
    end
  else
    puts "virtual type: #{options[:virtual_type]}, must be one of static, mapped, or dynamic"
    exit false
  end
elsif options[:virtual_content] || options[:virtual_name] || options[:virtual_type]
  puts 'the --virtual-* flags are only used when all are specified'
  exit false
end

server.add_share(virtual_disk)

RubySMB::Server::Cli.run(server)
