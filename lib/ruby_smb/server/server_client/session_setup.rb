module RubySMB
  class Server
    class ServerClient
      module SessionSetup
        def handle_session_setup1(raw_request)
          request = SMB2::Packet::SessionSetupRequest.read(raw_request)

          begin
            gss_api = OpenSSL::ASN1.decode(request.buffer)
          rescue OpenSSL::ASN1::ASN1Error
            disconnect!
            return
          end

          unless Gss.asn1dig(gss_api, 0)&.value == Gss::OID_SPNEGO.value
            disconnect!
            return
          end

          unless Gss.asn1dig(gss_api, 1, 0, 0, 0, 0)&.value == Gss::OID_NTLMSSP.value
            disconnect!
            return
          end

          raw_type1_msg = Gss.asn1dig(gss_api, 1, 0, 1, 0)&.value
          unless raw_type1_msg
            disconnect!
            return
          end

          type1_msg = Net::NTLM::Message::Type1.parse(raw_type1_msg)
          type2_msg = Net::NTLM::Message::Type2.new.tap do |msg|
            msg.target_name = 'LOCALHOST'.encode('UTF-16LE').b
            msg.flag = 0xe28a8215
            msg.challenge = SecureRandom.bytes(8).unpack1('Q')
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
            msg.os_version = "\x06\x01\x00\x00\x00\x00\x00\x0f".b # Version 6.1 (Build 0); NTLM Current Revision 15
            msg.enable(:os_version)
          end

          response = SMB2::Packet::SessionSetupResponse.new
          response.smb2_header.nt_status = WindowsError::NTStatus::STATUS_MORE_PROCESSING_REQUIRED.value
          response.smb2_header.credits = 1
          response.smb2_header.message_id = 1
          response.smb2_header.session_id = SecureRandom.random_bytes(4).unpack1('V')
          response.set_type2_blob(type2_msg.serialize)
          send_packet(response)
          @state = :session_setup2
        end

        def handle_session_setup2(raw_request)
          request = SMB2::Packet::SessionSetupRequest.read(raw_request)

          begin
            gss_api = OpenSSL::ASN1.decode(request.buffer)
          rescue OpenSSL::ASN1::ASN1Error
            disconnect!
            return
          end

          # fix this, sometimes it's 010 when the client is windows, otherwise it's 000 when the client is RubySMB
          raw_type3_msg = Gss.asn1dig(gss_api, 0, 1, 0)&.value
          type3_msg = Net::NTLM::Message::Type1.parse(raw_type3_msg)

          gss = OpenSSL::ASN1::ASN1Data.new([
            OpenSSL::ASN1::Sequence.new([
              OpenSSL::ASN1::ASN1Data.new([
                OpenSSL::ASN1::Enumerated.new(OpenSSL::BN.new(0)),
              ], 0, :CONTEXT_SPECIFIC)
            ])
          ], 1, :CONTEXT_SPECIFIC)

          response = SMB2::Packet::SessionSetupResponse.new
          response.smb2_header.credits = 1
          response.smb2_header.message_id = 2
          response.buffer = gss.to_der
          send_packet(response)
          @state = :authenticated
        end
      end
    end
  end
end

