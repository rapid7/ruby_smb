require 'ruby_smb/ntlm'

module RubySMB
  module Gss
    module Provider
      #
      # A GSS provider that authenticates clients via the NT LAN Manager (NTLM) Security Support Provider (NTLMSSP)
      # protocol.
      #
      class NTLM < Base
        include RubySMB::NTLM

        # An account representing an identity for which this provider will accept authentication attempts.
        Account = Struct.new(:username, :password, :domain) do
          def to_s
            "#{domain}\\#{username}"
          end
        end

        class Authenticator < Authenticator::Base
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
            rescue OpenSSL::ASN1::ASN1Error => e
              logger.error("Failed to parse the ASN1-encoded authentication request (#{e.message})")
              return
            end

            if gss_api&.tag == 0 && gss_api&.tag_class == :APPLICATION
              result = process_gss_type1(gss_api)
            elsif gss_api&.tag == 1 && gss_api&.tag_class == :CONTEXT_SPECIFIC
              result = process_gss_type3(gss_api)
            end

            result
          end

          #
          # Process the NTLM type 1 message and build a type 2 response message.
          #
          # @param [Net::NTLM::Message::Type1] type1_msg the NTLM type 1 message received by the client that should be
          #   processed
          # @return [Net::NTLM::Message::Type2] the NTLM type 2 response message with which to reply to the client
          def process_ntlm_type1(type1_msg)
            type2_msg = Net::NTLM::Message::Type2.new.tap do |msg|
              msg.target_name = 'LOCALHOST'.encode('UTF-16LE').b
              msg.flag = 0
              %i{ KEY56 KEY128 KEY_EXCHANGE UNICODE TARGET_INFO VERSION_INFO }.each do |flag|
                msg.flag |= NTLM::NEGOTIATE_FLAGS.fetch(flag)
              end

              if type1_msg.flag & NTLM::NEGOTIATE_FLAGS[:EXTENDED_SECURITY] == NTLM::NEGOTIATE_FLAGS[:EXTENDED_SECURITY]
                msg.flag |= NTLM::NEGOTIATE_FLAGS[:EXTENDED_SECURITY]
              end

              @server_challenge = @provider.generate_server_challenge
              msg.challenge = @server_challenge.unpack1('Q<') # 64-bit unsigned, little endian (uint64_t)
              target_info = Net::NTLM::TargetInfo.new('')
              target_info.av_pairs.merge!({
                Net::NTLM::TargetInfo::MSV_AV_NB_DOMAIN_NAME => @provider.netbios_domain.encode('UTF-16LE').b,
                Net::NTLM::TargetInfo::MSV_AV_NB_COMPUTER_NAME => @provider.netbios_hostname.encode('UTF-16LE').b,
                Net::NTLM::TargetInfo::MSV_AV_DNS_DOMAIN_NAME => @provider.dns_domain.encode('UTF-16LE').b,
                Net::NTLM::TargetInfo::MSV_AV_DNS_COMPUTER_NAME => @provider.dns_hostname.encode('UTF-16LE').b,
                Net::NTLM::TargetInfo::MSV_AV_TIMESTAMP => [(Time.now.to_i + Net::NTLM::TIME_OFFSET) * Field::FileTime::NS_MULTIPLIER].pack('Q')
              })
              msg.target_info = target_info.to_s
              msg.enable(:target_info)
              msg.context = 0
              msg.enable(:context)
              msg.os_version = NTLM::OSVersion.new(major: 6, minor: 3).to_binary_s
              msg.enable(:os_version)
            end

            type2_msg
          end

          #
          # Process the NTLM type 3 message and either accept or reject the authentication attempt.
          #
          # @param [Net::NTLM::Message::Type3] type3_msg the NTLM type 3 message received by the client that should be
          #   processed
          # @return [WindowsError::ErrorCode] an NT Status error code representing the operations outcome where
          #   STATUS_SUCCESS is a successful authentication attempt and anything else is a failure
          def process_ntlm_type3(type3_msg)
            if type3_msg.user == '' && type3_msg.domain == ''
              if @provider.allow_anonymous
                @session_key = "\x00".b * 16 # see MS-NLMP section 3.4
                return WindowsError::NTStatus::STATUS_SUCCESS
              end

              return WindowsError::NTStatus::STATUS_LOGON_FAILURE
            end

            dbg_string = "#{type3_msg.domain.encode(''.encoding)}\\#{type3_msg.user.encode(''.encoding)}"
            logger.debug("NTLM authentication request received for #{dbg_string}")
            account = @provider.get_account(
              type3_msg.user,
              domain: type3_msg.domain
            )
            if account.nil?
              if @provider.allow_guests
                logger.info("NTLM authentication request succeeded for #{dbg_string} (guest)")
                @session_key = "\x00".b * 16 # see MS-NLMP section 3.4
                return WindowsError::NTStatus::STATUS_SUCCESS
              end

              logger.info("NTLM authentication request failed for #{dbg_string} (no account)")
              return WindowsError::NTStatus::STATUS_LOGON_FAILURE
            end

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
                if type3_msg.flag & NTLM::NEGOTIATE_FLAGS[:KEY_EXCHANGE] == NTLM::NEGOTIATE_FLAGS[:KEY_EXCHANGE] && type3_msg.session_key.length == 16
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

            unless matches
              logger.info("NTLM authentication request failed for #{dbg_string} (bad password)")
              return WindowsError::NTStatus::STATUS_LOGON_FAILURE
            end

            logger.info("NTLM authentication request succeeded for #{dbg_string}")
            WindowsError::NTStatus::STATUS_SUCCESS
          end

          attr_accessor :server_challenge

          private

          # take the GSS blob, extract the NTLM type 1 message and pass it to the process method to build the response
          # which is then put back into a new GSS reply-blob
          def process_gss_type1(gss_api)
            unless Gss.asn1dig(gss_api, 1, 0, 0, 0, 0)&.value == Gss::OID_NTLMSSP.value
              return
            end

            raw_type1_msg = Gss.asn1dig(gss_api, 1, 0, 1, 0)&.value
            return unless raw_type1_msg

            type1_msg = Net::NTLM::Message.parse(raw_type1_msg)
            if type1_msg.flag & NTLM::NEGOTIATE_FLAGS[:UNICODE] == NTLM::NEGOTIATE_FLAGS[:UNICODE]
              type1_msg.domain.force_encoding('UTF-16LE')
              type1_msg.workstation.force_encoding('UTF-16LE')
            end
            type2_msg = process_ntlm_type1(type1_msg)

            Result.new(Gss.gss_type2(type2_msg.serialize), WindowsError::NTStatus::STATUS_MORE_PROCESSING_REQUIRED)
          end

          # take the GSS blob, extract the NTLM type 3 message and pass it to the process method to build the response
          # which is then put back into a new GSS reply-blob
          def process_gss_type3(gss_api)
            neg_token_init = Hash[RubySMB::Gss.asn1dig(gss_api, 0).value.map { |obj| [obj.tag, obj.value[0].value] }]
            raw_type3_msg = neg_token_init[2]

            type3_msg = Net::NTLM::Message.parse(raw_type3_msg)
            if type3_msg.flag & NTLM::NEGOTIATE_FLAGS[:UNICODE] == NTLM::NEGOTIATE_FLAGS[:UNICODE]
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

              account = @provider.get_account(
                type3_msg.user,
                domain: type3_msg.domain
              )
              if account.nil?
                if type3_msg.user == ''
                  is_guest = false
                  identity = IDENTITY_ANONYMOUS
                else
                  is_guest = true
                  identity = Account.new(type3_msg.user.encode(''.encoding), '', type3_msg.domain.encode(''.encoding)).to_s
                end
              else
                is_guest = false
                identity = account.to_s
              end
            end

            Result.new(buffer, nt_status, identity, is_guest)
          end
        end

        # @param [Boolean] allow_anonymous whether or not to allow anonymous authentication attempts
        # @param [String] default_domain the default domain to use for authentication, unless specified 'WORKGROUP' will
        #   be used
        def initialize(allow_anonymous: false, allow_guests: false, default_domain: 'WORKGROUP')
          raise ArgumentError, 'Must specify a default domain' unless default_domain

          @allow_anonymous = allow_anonymous
          @allow_guests = allow_guests
          @default_domain = default_domain
          @accounts = []
          @generate_server_challenge = -> { SecureRandom.bytes(8) }

          @dns_domain = @netbios_domain = 'LOCALDOMAIN'
          @dns_hostname = @netbios_hostname = 'LOCALHOST'
        end

        #
        # Generate the 8-byte server challenge. If a block is specified, it's used as the challenge generation routine
        # and should return an 8-byte value.
        #
        # @return [String] an 8-byte challenge value
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

        #
        # Lookup and return an account based on the username and optionally, the domain. If no domain is specified or
        # or it is the special value '.', the default domain will be used. The username and domain values are case
        # insensitive.
        #
        # @param [String] username the username of the account to fetch.
        # @param [String, nil] domain the domain in which the account to fetch exists.
        # @return [Account, nil] the account if it was found
        def get_account(username, domain: nil)
          # the username and password values should use the native encoding for the comparison in the #find operation
          username = username.downcase
          domain = @default_domain if domain.nil? || domain == '.'.encode(domain.encoding)
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
          domain = @default_domain if domain.nil? || domain == '.'.encode(domain.encoding)
          @accounts << Account.new(username, password, domain)
        end

        #
        # The default domain value to use for accounts which do not have one specified or use the special '.' value.
        attr_reader :default_domain

        attr_accessor :dns_domain, :dns_hostname, :netbios_domain, :netbios_hostname
      end
    end
  end
end
