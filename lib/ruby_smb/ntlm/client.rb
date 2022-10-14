class Net::NTLM::EncodeUtil
  def self.encode_utf16le(str)
    str.dup.force_encoding('UTF-8').encode(Encoding::UTF_16LE, Encoding::UTF_8).force_encoding('ASCII-8BIT')
  end
end

module RubySMB::NTLM
  module Message
    def deflag
      security_buffers.inject(head_size) do |cur, a|
        a[1].offset = cur
        cur += a[1].data_size
        has_flag?(:UNICODE) ? cur + cur % 2 : cur
      end
    end

    def serialize
      deflag
      @alist.map { |n, f| f.serialize }.join + security_buffers.map { |n, f| f.value + (has_flag?(:UNICODE) ? "\x00".b * (f.value.length % 2) : '') }.join
    end
  end

  class Client < Net::NTLM::Client
    class Session < Net::NTLM::Client::Session
      def authenticate!
        calculate_user_session_key!
        type3_opts = {
          :lm_response   => is_anonymous? ? "\x00".b : lmv2_resp,
          :ntlm_response => is_anonymous? ? '' : ntlmv2_resp,
          :domain        => domain,
          :user          => username,
          :workstation   => workstation,
          :flag          => (challenge_message.flag & client.flags)
        }
        t3 = Net::NTLM::Message::Type3.create type3_opts
        t3.extend(Message)
        if negotiate_key_exchange?
          t3.enable(:session_key)
          rc4 = OpenSSL::Cipher.new("rc4")
          rc4.encrypt
          rc4.key = user_session_key
          sk = rc4.update exported_session_key
          sk << rc4.final
          t3.session_key = sk
        end
        t3
      end

      def is_anonymous?
        username == '' && password == ''
      end

      private

      def use_oem_strings?
        # @see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832
        !challenge_message.has_flag?(:UNICODE) && challenge_message.has_flag?(:OEM)
      end

      def ntlmv2_hash
        @ntlmv2_hash ||= RubySMB::NTLM.ntlmv2_hash(username, password, domain, {:client_challenge => client_challenge, :unicode => !use_oem_strings?})
      end

      def calculate_user_session_key!
        if is_anonymous?
          # see MS-NLMP section 3.4
          @user_session_key = "\x00".b * 16
        else
          @user_session_key = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmv2_hash, nt_proof_str)
        end
      end
    end

    def init_context(resp = nil, channel_binding = nil)
      if resp.nil?
        @session = nil
        type1_message
      else
        @session = Client::Session.new(self, Net::NTLM::Message.decode64(resp), channel_binding)
        @session.authenticate!
      end
    end
  end
end
