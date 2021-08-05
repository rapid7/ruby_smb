module RubySMB
  module Gss
    module Provider
      class NTLM < Base
        Account = Struct.new(:username, :password, :domain) do
          def to_s
            "#{domain}\\#{username}"
          end
        end

        class Authenticator < Authenticator::Base
          NEGOTIATE_FLAGS = {
            :UNICODE                  => 1 << 0,
            :OEM                      => 1 << 1,
            :REQUEST_TARGET           => 1 << 2,
            :SIGN                     => 1 << 4,
            :SEAL                     => 1 << 5,
            :DATAGRAM                 => 1 << 6,
            :LAN_MANAGER_KEY          => 1 << 7,
            :NTLM                     => 1 << 9,
            :NT_ONLY                  => 1 << 10,
            :ANONYMOUS                => 1 << 11,
            :OEM_DOMAIN_SUPPLIED      => 1 << 12,
            :OEM_WORKSTATION_SUPPLIED => 1 << 13,
            :ALWAYS_SIGN              => 1 << 15,
            :TARGET_TYPE_DOMAIN       => 1 << 16,
            :TARGET_TYPE_SERVER       => 1 << 17,
            :TARGET_TYPE_SHARE        => 1 << 18,
            :EXTENDED_SECURITY        => 1 << 19,
            :IDENTIFY                 => 1 << 20,
            :NON_NT_SESSION           => 1 << 22,
            :TARGET_INFO              => 1 << 23,
            :VERSION_INFO             => 1 << 25,
            :KEY128                   => 1 << 29,
            :KEY_EXCHANGE             => 1 << 30,
            :KEY56                    => 1 << 31
          }.freeze

          def reset!
            super
            @server_challenge = nil
          end

          def process(request_buffer=nil)
            if request_buffer.nil?
              # this is only NTLMSSP (as opposed to SPNEGO + NTLMSSP)
              buffer = OpenSSL::ASN1::ASN1Data.new([
                Gss::OID_SPNEGO,
                OpenSSL::ASN1::ASN1Data.new([
                  OpenSSL::ASN1::Sequence.new([
                    OpenSSL::ASN1::ASN1Data.new([
                      OpenSSL::ASN1::Sequence.new([
                        Gss::OID_NTLMSSP
                      ])
                    ], 0, :CONTEXT_SPECIFIC),
                    OpenSSL::ASN1::ASN1Data.new([
                      OpenSSL::ASN1::ASN1Data.new([
                        OpenSSL::ASN1::ASN1Data.new([
                          OpenSSL::ASN1::GeneralString.new('not_defined_in_RFC4178@please_ignore')
                        ], 0, :CONTEXT_SPECIFIC)
                      ], 16, :UNIVERSAL)
                    ], 3, :CONTEXT_SPECIFIC)
                  ])
                ], 0, :CONTEXT_SPECIFIC)
              ], 0, :APPLICATION).to_der
              return Result.new(buffer, WindowsError::NTStatus::STATUS_SUCCESS)
            end

            begin
              gss_api = OpenSSL::ASN1.decode(request_buffer)
            rescue OpenSSL::ASN1::ASN1Error
              return
            end

            if gss_api&.tag == 0 && gss_api&.tag_class == :APPLICATION
              result = process_gss_type1(gss_api)
            elsif gss_api&.tag == 1 && gss_api&.tag_class == :CONTEXT_SPECIFIC
              result = process_gss_type3(gss_api)
            end

            result
          end

          def process_ntlm_type1(type1_msg)
            type2_msg = Net::NTLM::Message::Type2.new.tap do |msg|
              msg.target_name = 'LOCALHOST'.encode('UTF-16LE').b
              msg.flag = 0
              %i{ KEY56 KEY128 KEY_EXCHANGE UNICODE TARGET_INFO VERSION_INFO }.each do |flag|
                msg.flag |= NEGOTIATE_FLAGS.fetch(flag)
              end

              @server_challenge = @provider.generate_server_challenge
              msg.challenge = @server_challenge.unpack1('Q')
              target_info = Net::NTLM::TargetInfo.new('')
              target_info.av_pairs.merge!({
                Net::NTLM::TargetInfo::MSV_AV_NB_DOMAIN_NAME => 'LOCALHOST'.encode('UTF-16LE').b,
                Net::NTLM::TargetInfo::MSV_AV_NB_COMPUTER_NAME => 'LOCALHOST'.encode('UTF-16LE').b,
                Net::NTLM::TargetInfo::MSV_AV_DNS_DOMAIN_NAME => "\x00\x00".b,
                Net::NTLM::TargetInfo::MSV_AV_DNS_COMPUTER_NAME => 'LOCALHOST'.encode('UTF-16LE').b,
                Net::NTLM::TargetInfo::MSV_AV_TIMESTAMP => [(Time.now.to_i + Net::NTLM::TIME_OFFSET) * Field::FileTime::NS_MULTIPLIER].pack('Q')
              })
              msg.target_info = target_info.to_s
              msg.enable(:target_info)
              msg.context = 0
              msg.enable(:context)
              msg.os_version = [ 6, 1, 0, 15].pack('CCnN') # Version 6.1 (Build 0); NTLM Current Revision 15
              msg.enable(:os_version)
            end

            type2_msg
          end

          def process_ntlm_type3(type3_msg)
            if type3_msg.user == '' && type3_msg.domain == ''
              if @provider.allow_anonymous
                return WindowsError::NTStatus::STATUS_SUCCESS
              end

              return WindowsError::NTStatus::STATUS_LOGON_FAILURE
            end

            account = @provider.get_account(
              type3_msg.user,
              domain: type3_msg.domain
            )
            return WindowsError::NTStatus::STATUS_LOGON_FAILURE if account.nil?

            matches = false
            case type3_msg.ntlm_version
            when :ntlmv1
              my_ntlm_response = Net::NTLM::ntlm_response(
                ntlm_hash: Net::NTLM::ntlm_hash(account.password.encode('UTF-16LE'), unicode: true),
                challenge: @server_challenge
              )
              matches = my_ntlm_response == type3_msg.ntlm_response
            when :ntlmv2
              digest = OpenSSL::Digest::MD5.new
              their_nt_proof_str = type3_msg.ntlm_response[0...digest.digest_length]
              their_blob = type3_msg.ntlm_response[digest.digest_length..-1]

              ntlmv2_hash = Net::NTLM.ntlmv2_hash(
                account.username.encode('UTF-16LE'),
                account.password.encode('UTF-16LE'),
                type3_msg.domain.encode('UTF-16LE'),  # don't use the account domain because of the special '.' value
                {client_challenge: their_blob[16...24], unicode: true}
              )

              my_nt_proof_str = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmv2_hash, @server_challenge + their_blob)
              matches = my_nt_proof_str == their_nt_proof_str
              if matches
                user_session_key = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmv2_hash, my_nt_proof_str)
                if type3_msg.flag & NEGOTIATE_FLAGS[:KEY_EXCHANGE] == NEGOTIATE_FLAGS[:KEY_EXCHANGE]
                  rc4 = OpenSSL::Cipher.new('rc4')
                  rc4.decrypt
                  rc4.key = user_session_key
                  @session_key = rc4.update type3_msg.session_key
                  @session_key << rc4.final
                else
                  @session_key = user_session_key
                end
              end
            else
              # the only other value Net::NTLM will return for this is ntlm_session
              raise NotImplementedError, "authentication via ntlm version #{type3_msg.ntlm_version} is not supported"
            end

            return WindowsError::NTStatus::STATUS_LOGON_FAILURE unless matches

            WindowsError::NTStatus::STATUS_SUCCESS
          end

          private

          def process_gss_type1(gss_api)
            unless Gss.asn1dig(gss_api, 1, 0, 0, 0, 0)&.value == Gss::OID_NTLMSSP.value
              return
            end

            raw_type1_msg = Gss.asn1dig(gss_api, 1, 0, 1, 0)&.value
            return unless raw_type1_msg

            type1_msg = Net::NTLM::Message.parse(raw_type1_msg)
            if type1_msg.flag & NEGOTIATE_FLAGS[:UNICODE] == NEGOTIATE_FLAGS[:UNICODE]
              type1_msg.domain.force_encoding('UTF-16LE')
              type1_msg.workstation.force_encoding('UTF-16LE')
            end
            type2_msg = process_ntlm_type1(type1_msg)

            Result.new(Gss.gss_type2(type2_msg.serialize), WindowsError::NTStatus::STATUS_MORE_PROCESSING_REQUIRED)
          end

          def process_gss_type3(gss_api)
            neg_token_init = Hash[RubySMB::Gss.asn1dig(gss_api, 0).value.map { |obj| [obj.tag, obj.value[0].value] }]
            raw_type3_msg = neg_token_init[2]

            type3_msg = Net::NTLM::Message.parse(raw_type3_msg)
            if type3_msg.flag & NEGOTIATE_FLAGS[:UNICODE] == NEGOTIATE_FLAGS[:UNICODE]
              type3_msg.domain.force_encoding('UTF-16LE')
              type3_msg.user.force_encoding('UTF-16LE')
              type3_msg.workstation.force_encoding('UTF-16LE')
            end

            nt_status = process_ntlm_type3(type3_msg)
            buffer = identity = nil

            case nt_status
            when WindowsError::NTStatus::STATUS_SUCCESS
              buffer = OpenSSL::ASN1::ASN1Data.new([
                OpenSSL::ASN1::Sequence.new([
                  OpenSSL::ASN1::ASN1Data.new([
                    OpenSSL::ASN1::Enumerated.new(OpenSSL::BN.new(0)),
                  ], 0, :CONTEXT_SPECIFIC)
                ])
              ], 1, :CONTEXT_SPECIFIC).to_der
            end

            account = @provider.get_account(
              type3_msg.user,
              domain: type3_msg.domain
            )
            if account.nil?
              if @provider.allow_anonymous
                identity = IDENTITY_ANONYMOUS
              end
            else
              identity = account.to_s
            end

            Result.new(buffer, nt_status, identity)
          end
        end

        def initialize(allow_anonymous: false, default_domain: nil)
          @allow_anonymous = allow_anonymous
          @default_domain = default_domain || 'WORKGROUP'
          @accounts = []
          @generate_server_challenge = -> { SecureRandom.bytes(8) }
        end

        def generate_server_challenge(&block)
          if block.nil?
            @generate_server_challenge.call
          else
            @generate_server_challenge = block
          end
        end

        def new_authenticator(server_client)
          # build and return an instance that can process and track stateful information for a particular connection but
          # that's backed by this particular provider
          Authenticator.new(self, server_client)
        end

        def get_account(username, domain: nil)
          # the username and password values should use the native encoding for the comparison in the #find operation
          username = username.downcase
          domain = @default_domain if domain == '.'.encode(domain.encoding) || domain.nil?
          domain = domain.downcase
          @accounts.find { |account| account.username.encode(username.encoding).downcase == username && account.domain.encode(domain.encoding).downcase == domain }
        end

        #
        # Add an account to the database.
        #
        # @param [String] username the username of the account to add
        # @param [String] password either the plaintext password or the NTLM hash of the account to add
        # @param [String] domain the domain of the account to add, if not specified, the @default_domain will be used
        def put_account(username, password, domain: nil)
          domain = @default_domain if domain == '.' || domain.nil?
          @accounts << Account.new(username, password, domain)
        end

        attr_reader :default_domain
      end
    end
  end
end
