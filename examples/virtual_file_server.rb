#!/usr/bin/ruby

require 'bundler/setup'
require 'optparse'
require 'ruby_smb'
require 'ruby_smb/gss/provider/ntlm'

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

options = {
  allow_anonymous: true,
  domain: nil,
  username: 'RubySMB',
  password: 'password',
  share_name: 'home',
  smbv1: true,
  smbv2: true,
  smbv3: true
}
OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename(__FILE__)} [options]"
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
  opts.on("--virtual-content CONTENT", "The virtual share contents") do |virtual_content|
    options[:virtual_content] = virtual_content
  end
  opts.on("--virtual-name NAME", "The virtual share file name") do |virtual_name|
    options[:virtual_name] = virtual_name
  end
  opts.on("--virtual-type TYPE", "The virtual share type") do |virtual_type|
    options[:virtual_type] = virtual_type
  end
end.parse!

ntlm_provider = RubySMB::Gss::Provider::NTLM.new(allow_anonymous: options[:allow_anonymous])
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
puts "server is running"
server.run do |server_client|
  puts "received connection"
  true
end

