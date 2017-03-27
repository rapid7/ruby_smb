require 'spec_helper'

RSpec.describe RubySMB::Client do

  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(nil) }
  let(:username) { 'msfadmin' }
  let(:password) { 'msfadmin' }
  subject(:client) { described_class.new(dispatcher, username: username, password: password) }
  let(:smb1_client) { described_class.new(dispatcher, smb2:false, username: username, password: password) }
  let(:smb2_client) { described_class.new(dispatcher, smb1:false, username: username, password: password) }

  describe '#initialize' do
    it 'should raise an ArgumentError without a valid dispatcher' do
      expect{ described_class.new(nil) }.to raise_error(ArgumentError)
    end

    it 'defaults to true for SMB1 support' do
      expect(client.smb1).to be true
    end

    it 'defaults to true for SMB2 support' do
      expect(client.smb1).to be true
    end

    it 'accepts an argument to disable smb1 support' do
      smb_client = described_class.new(dispatcher, smb1:false, username: username, password: password)
      expect(smb_client.smb1).to be false
    end

    it 'accepts an argument to disable smb2 support' do
      expect(smb1_client.smb2).to be false
    end

    it 'raises an exception if both SMB1 and SMB2 are disabled' do
      expect{described_class.new(dispatcher, smb1:false, smb2:false, username: username, password: password)}.to raise_error(ArgumentError, 'You must enable at least one Protocol')
    end

    it 'sets the username attribute'  do
      expect(client.username).to eq username
    end

    it 'sets the password attribute' do
      expect(client.password).to eq password
    end

    it 'crates an NTLM client' do
      expect(client.ntlm_client).to be_a Net::NTLM::Client
    end
  end

  describe '#send_recv' do
    let(:smb1_request) { RubySMB::SMB1::Packet::SessionSetupRequest.new }
    let(:smb2_request) { RubySMB::SMB2::Packet::SessionSetupRequest.new }

    before(:each) do
      expect(dispatcher).to receive(:send_packet).and_return(nil)
      expect(dispatcher).to receive(:recv_packet).and_return("A")
    end

    it 'checks the packet version' do
      expect(smb1_request).to receive(:packet_smb_version).and_call_original
      client.send_recv(smb1_request)
    end

    it 'calls #smb1_sign if it is an SMB1 packet'  do
      expect(client).to receive(:smb1_sign).with(smb1_request).and_call_original
      client.send_recv(smb1_request)
    end

    it 'calls #smb2_sign if it is an SMB2 packet' do
      expect(client).to receive(:smb2_sign).with(smb2_request).and_call_original
      client.send_recv(smb2_request)
    end

  end

  context 'Protocol Negotiation' do
    let(:random_junk) { "fgrgrwgawrtw4t4tg4gahgn" }
    let(:smb1_capabilities) {
      {:level_2_oplocks=>1,
       :nt_status=>1,
       :rpc_remote_apis=>1,
       :nt_smbs=>1,
       :large_files=>1,
       :unicode=>1,
       :mpx_mode=>0,
       :raw_mode=>0,
       :large_writex=>1,
       :large_readx=>1,
       :info_level_passthru=>1,
       :dfs=>0,
       :reserved1=>0,
       :bulk_transfer=>0,
       :nt_find=>1,
       :lock_and_read=>1,
       :unix=>0,
       :reserved2=>0,
       :lwio=>1,
       :extended_security=>1,
       :reserved3=>0,
       :dynamic_reauth=>0,
       :reserved4=>0,
       :compressed_data=>0,
       :reserved5=>0}
    }
    let(:smb1_extended_response) {
      packet = RubySMB::SMB1::Packet::NegotiateResponseExtended.new
      packet.parameter_block.capabilities = smb1_capabilities
      packet
    }
    let(:smb1_extended_response_raw) {
      smb1_extended_response.to_binary_s
    }

    let(:smb2_response) { RubySMB::SMB2::Packet::NegotiateResponse.new }

    describe '#smb1_negotiate_request' do
      it 'returns an SMB1 Negotiate Request packet' do
        expect(client.smb1_negotiate_request).to be_a(RubySMB::SMB1::Packet::NegotiateRequest)
      end

      it 'sets the default SMB1 Dialect' do
        expect(client.smb1_negotiate_request.dialects).to include({:buffer_format=>2, :dialect_string=> RubySMB::Client::SMB1_DIALECT_SMB1_DEFAULT})
      end

      it 'sets the SMB2.02 dialect if SMB2 support is enabled' do
        expect(client.smb1_negotiate_request.dialects).to include({:buffer_format=>2, :dialect_string=> RubySMB::Client::SMB1_DIALECT_SMB2_DEFAULT})
      end

      it 'excludes the SMB2.02 Dialect if SMB2 support is disabled' do
        expect(smb1_client.smb1_negotiate_request.dialects).to_not include({:buffer_format=>2, :dialect_string=> RubySMB::Client::SMB1_DIALECT_SMB2_DEFAULT})
      end

      it 'excludes the default SMB1 Dialect if SMB1 support is disabled' do
        expect(smb2_client.smb1_negotiate_request.dialects).to_not include({:buffer_format=>2, :dialect_string=> RubySMB::Client::SMB1_DIALECT_SMB1_DEFAULT})
      end
    end

    describe '#smb2_negotiate_request' do
      it 'return an SMB2 Negotiate Request packet' do
        expect(client.smb2_negotiate_request).to be_a(RubySMB::SMB2::Packet::NegotiateRequest)
      end

      it 'sets the default SMB2 Dialect' do
        expect(client.smb2_negotiate_request.dialects).to include(RubySMB::Client::SMB2_DIALECT_DEFAULT)
      end

      it 'sets the Message ID to 0' do
        expect(client.smb2_negotiate_request.smb2_header.message_id).to eq 0
      end
    end

    describe '#negotiate_request' do
      it 'calls #smb1_negotiate_request if SMB1 is enabled' do
        expect(smb1_client).to receive(:smb1_negotiate_request)
        expect(smb1_client).to receive(:send_recv)
        smb1_client.negotiate_request
      end

      it 'calls #smb1_negotiate_request if both protocols are enabled' do
        expect(client).to receive(:smb1_negotiate_request)
        expect(client).to receive(:send_recv)
        client.negotiate_request
      end

      it 'calls #smb2_negotiate_request if SMB2 is enabled' do
        expect(smb2_client).to receive(:smb2_negotiate_request)
        expect(smb2_client).to receive(:send_recv)
        smb2_client.negotiate_request
      end

      it 'returns the raw response string from the server' do
        expect(client).to receive(:send_recv).and_return('A')
        expect(client.negotiate_request).to eq "A"
      end
    end

    describe '#negotiate_response' do
      context 'with only SMB1' do
        it 'returns a properly formed packet' do
          expect(smb1_client.negotiate_response(smb1_extended_response_raw)).to eq smb1_extended_response
        end

        it 'raises an exception if the Response is invalid' do
          expect{ smb1_client.negotiate_response(random_junk) }.to raise_error(RubySMB::Error::InvalidPacket)
        end

        it 'considers the response invalid if it is not an actual Negotiate Response' do
          bogus_response = smb1_extended_response
          bogus_response.smb_header.command = 0xff
          expect{ smb1_client.negotiate_response(bogus_response.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end

        it 'considers the response invalid if Extended Security is not enabled' do
          bogus_response = smb1_extended_response
          bogus_response.parameter_block.capabilities.extended_security = 0
          expect{ smb1_client.negotiate_response(bogus_response.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'with only SMB2' do
        it 'returns a properly formed packet' do
          expect( smb2_client.negotiate_response(smb2_response.to_binary_s) ).to eq smb2_response
        end

        it 'raises an exception if the Response is invalid' do
          expect{ smb2_client.negotiate_response(random_junk) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      context 'with SMB1 and SMB2 enabled' do
        it 'returns an SMB1 NegotiateResponse if it looks like SMB1' do
          expect( client.negotiate_response(smb1_extended_response_raw) ).to eq smb1_extended_response
        end

        it 'returns an SMB2 NegotiateResponse if it looks like SMB2' do
          expect( client.negotiate_response(smb2_response.to_binary_s) ).to eq smb2_response
        end
      end
    end

    describe '#parse_negotiate_response' do
      context 'when SMB1 was Negotiated' do
        it 'turns off SMB2 support' do
          client.parse_negotiate_response(smb1_extended_response)
          expect( client.smb2 ).to be false
        end

        it 'sets whether or not signing is required' do
          smb1_extended_response.parameter_block.security_mode.security_signatures_required = 1
          client.parse_negotiate_response(smb1_extended_response)
          expect(client.signing_required).to be true
        end
      end

      context 'when SMB2 was negotiated' do
        it 'turns off SMB1 support' do
          client.parse_negotiate_response(smb2_response)
          expect( client.smb1 ).to be false
        end

        it 'sets whether or not signing is required' do
          smb2_response.security_mode.signing_required = 1
          client.parse_negotiate_response(smb2_response)
          expect(client.signing_required).to be true
        end
      end
    end

    describe '#negotiate' do
      it 'calls the backing methods' do
        expect(client).to receive(:negotiate_request)
        expect(client).to receive(:negotiate_response)
        expect(client).to receive(:parse_negotiate_response)
        client.negotiate
      end
    end
  end

  context 'Authentication' do
    let(:type2_string) {
      "TlRMTVNTUAACAAAAHgAeADgAAAA1goriwmZ8HEHtFHAAAAAAAAAAAJgAmABW\nAAAABgGxHQAAAA" +
        "9XAEkATgAtAFMATgBKAEQARwAwAFUAQQA5ADAARgACAB4A\nVwBJAE4ALQBTAE4ASgBEAEcAMABV" +
        "AEEAOQAwAEYAAQAeAFcASQBOAC0AUwBO\nAEoARABHADAAVQBBADkAMABGAAQAHgBXAEkATgAtAF" +
        "MATgBKAEQARwAwAFUA\nQQA5ADAARgADAB4AVwBJAE4ALQBTAE4ASgBEAEcAMABVAEEAOQAwAEYABw" +
        "AI\nADxThZ4nnNIBAAAAAA==\n"
    }
    context 'for SMB1' do
      let(:ntlm_client)  { smb1_client.ntlm_client }
      let(:type1_message)  { ntlm_client.init_context }
      let(:negotiate_packet) { RubySMB::SMB1::Packet::SessionSetupRequest.new }
      let(:type3_message) { ntlm_client.init_context(type2_string) }
      let(:user_id) { 2041 }


      describe '#smb1_ntlmssp_auth_packet' do
        it 'creates a new SessionSetupRequest packet' do
          expect(RubySMB::SMB1::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          smb1_client.smb1_ntlmssp_auth_packet(type2_string, user_id)
        end

        it 'builds the security blob with an NTLM Type 3 Message' do
          expect(RubySMB::SMB1::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          expect(ntlm_client).to receive(:init_context).with(type2_string).and_return(type3_message)
          expect(negotiate_packet).to receive(:set_type3_blob).with(type3_message.serialize)
          smb1_client.smb1_ntlmssp_auth_packet(type2_string, user_id)
        end

        it 'enables extended security on the packet' do
          expect(smb1_client.smb1_ntlmssp_auth_packet(type2_string, user_id).smb_header.flags2.extended_security).to eq 1
        end
      end

      describe '#smb1_ntlmssp_negotiate_packet' do
        it 'creates a new SessionSetupRequest packet' do
          expect(RubySMB::SMB1::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          smb1_client.smb1_ntlmssp_negotiate_packet
        end

        it 'builds the security blob with an NTLM Type 1 Message' do
          expect(RubySMB::SMB1::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          expect(ntlm_client).to receive(:init_context).and_return(type1_message)
          expect(negotiate_packet).to receive(:set_type1_blob).with(type1_message.serialize)
          smb1_client.smb1_ntlmssp_negotiate_packet
        end

        it 'enables extended security on the packet' do
          expect(smb1_client.smb1_ntlmssp_negotiate_packet.smb_header.flags2.extended_security).to eq 1
        end
      end

      describe '#smb1_ntlmssp_authenticate' do
        it 'sends the request packet and receives a response' do
          expect(smb1_client).to receive(:smb1_ntlmssp_auth_packet).and_return(negotiate_packet)
          expect(dispatcher).to receive(:send_packet).with(negotiate_packet)
          expect(dispatcher).to receive(:recv_packet)
          smb1_client.smb1_ntlmssp_authenticate(type2_string, user_id)
        end
      end

      describe '#smb1_ntlmssp_negotiate' do
        it 'sends the request packet and receives a response' do
          expect(smb1_client).to receive(:smb1_ntlmssp_negotiate_packet).and_return(negotiate_packet)
          expect(dispatcher).to receive(:send_packet).with(negotiate_packet)
          expect(dispatcher).to receive(:recv_packet)
          smb1_client.smb1_ntlmssp_negotiate
        end
      end

      describe '#smb1_ntlmssp_challenge_packet' do
        let(:response) {
          packet = RubySMB::SMB1::Packet::SessionSetupResponse.new
          packet.smb_header.nt_status = 0xc0000016
          packet
        }
        let(:wrong_command) {
          packet = RubySMB::SMB1::Packet::SessionSetupResponse.new
          packet.smb_header.nt_status = 0xc0000016
          packet.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
          packet
        }
        it 'returns the packet object' do
          expect(smb1_client.smb1_ntlmssp_challenge_packet(response.to_binary_s)).to eq response
        end

        it 'raises an UnexpectedStatusCode if the status code is not correct' do
          response.smb_header.nt_status = 0xc0000015
          expect{ smb1_client.smb1_ntlmssp_challenge_packet(response.to_binary_s) }.to raise_error( RubySMB::Error::UnexpectedStatusCode)
        end

        it 'raises an InvalidPacket if the Command field is wrong' do
          expect{ smb1_client.smb1_ntlmssp_challenge_packet(wrong_command.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      describe '#smb1_ntlmssp_final_packet' do
        let(:response) {
          packet = RubySMB::SMB1::Packet::SessionSetupResponse.new
          packet.smb_header.nt_status = 0x00000000
          packet
        }
        let(:wrong_command) {
          packet = RubySMB::SMB1::Packet::SessionSetupResponse.new
          packet.smb_header.nt_status = 0x00000000
          packet.smb_header.command = RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
          packet
        }
        it 'returns the packet object' do
          expect(smb1_client.smb1_ntlmssp_final_packet(response.to_binary_s)).to eq response
        end

        it 'raises an InvalidPacket if the Command field is wrong' do
          expect{ smb1_client.smb1_ntlmssp_final_packet(wrong_command.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      describe '#smb1_type2_message' do
        let(:fake_type2) { "NTLMSSP FOO" }
        let(:response_packet) {
          packet = RubySMB::SMB1::Packet::SessionSetupResponse.new
          packet.set_type2_blob(fake_type2)
          packet
        }
        it 'returns a base64 encoded copy of the Type 2 NTLM message' do
          expect(smb1_client.smb1_type2_message(response_packet)).to eq [fake_type2].pack('m')
        end
      end
    end

    context 'for SMB2' do
      let(:ntlm_client) { smb2_client.ntlm_client }
      let(:type1_message)  { ntlm_client.init_context }
      let(:negotiate_packet) { RubySMB::SMB2::Packet::SessionSetupRequest.new }
      let(:type3_message) { ntlm_client.init_context(type2_string) }
      let(:session_id) { 0x0000040000000005 }

      describe '#smb2_ntlmssp_negotiate_packet' do
        it 'creates a new SessionSetupRequest packet' do
          expect(RubySMB::SMB2::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          smb2_client.smb2_ntlmssp_negotiate_packet
        end

        it 'builds the security blob with an NTLM Type 1 Message' do
          expect(RubySMB::SMB2::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          expect(ntlm_client).to receive(:init_context).and_return(type1_message)
          expect(negotiate_packet).to receive(:set_type1_blob).with(type1_message.serialize)
          smb2_client.smb2_ntlmssp_negotiate_packet
        end

        it 'sets the message ID in the packet header to 1' do
          expect(smb2_client.smb2_ntlmssp_negotiate_packet.smb2_header.message_id).to eq 1
        end

        it 'increments client#smb2_message_id' do
          expect{ smb2_client.smb2_ntlmssp_negotiate_packet }.to change(smb2_client, :smb2_message_id).to(2)
        end
      end

      describe '#smb2_ntlmssp_negotiate' do
        it 'sends the request packet and receives a response' do
          expect(smb2_client).to receive(:smb2_ntlmssp_negotiate_packet).and_return(negotiate_packet)
          expect(dispatcher).to receive(:send_packet).with(negotiate_packet)
          expect(dispatcher).to receive(:recv_packet)
          smb2_client.smb2_ntlmssp_negotiate
        end
      end

      describe '#smb2_ntlmssp_challenge_packet' do
        let(:response) {
          packet = RubySMB::SMB2::Packet::SessionSetupResponse.new
          packet.smb2_header.nt_status = 0xc0000016
          packet
        }
        let(:wrong_command) {
          packet = RubySMB::SMB2::Packet::SessionSetupResponse.new
          packet.smb2_header.nt_status = 0xc0000016
          packet.smb2_header.command = RubySMB::SMB2::Commands::NEGOTIATE
          packet
        }
        it 'returns the packet object' do
          expect(smb2_client.smb2_ntlmssp_challenge_packet(response.to_binary_s)).to eq response
        end

        it 'raises an UnexpectedStatusCode if the status code is not correct' do
          response.smb2_header.nt_status = 0xc0000015
          expect{ smb2_client.smb2_ntlmssp_challenge_packet(response.to_binary_s) }.to raise_error( RubySMB::Error::UnexpectedStatusCode)
        end

        it 'raises an InvalidPacket if the Command field is wrong' do
          expect{ smb2_client.smb2_ntlmssp_challenge_packet(wrong_command.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end

      describe '#smb2_type2_message' do
        let(:fake_type2) { "NTLMSSP FOO" }
        let(:response_packet) {
          packet = RubySMB::SMB2::Packet::SessionSetupResponse.new
          packet.set_type2_blob(fake_type2)
          packet
        }
        it 'returns a base64 encoded copy of the Type 2 NTLM message' do
          expect(smb2_client.smb2_type2_message(response_packet)).to eq [fake_type2].pack('m')
        end
      end

      describe '#smb1_ntlmssp_auth_packet' do
        it 'creates a new SessionSetupRequest packet' do
          expect(RubySMB::SMB2::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          smb2_client.smb2_ntlmssp_auth_packet(type2_string, session_id)
        end

        it 'builds the security blob with an NTLM Type 3 Message' do
          expect(RubySMB::SMB2::Packet::SessionSetupRequest).to receive(:new).and_return(negotiate_packet)
          expect(ntlm_client).to receive(:init_context).with(type2_string).and_return(type3_message)
          expect(negotiate_packet).to receive(:set_type3_blob).with(type3_message.serialize)
          smb2_client.smb2_ntlmssp_auth_packet(type2_string, session_id)
        end

        it 'sets the session ID on the request packet' do
          expect(smb2_client.smb2_ntlmssp_auth_packet(type2_string, session_id).smb2_header.session_id).to eq session_id
        end

      end

      describe '#smb2_ntlmssp_authenticate' do
        it 'sends the request packet and receives a response' do
          expect(smb2_client).to receive(:smb2_ntlmssp_auth_packet).and_return(negotiate_packet)
          expect(dispatcher).to receive(:send_packet).with(negotiate_packet)
          expect(dispatcher).to receive(:recv_packet)
          smb2_client.smb2_ntlmssp_authenticate(type2_string, session_id)
        end
      end

      describe '#smb2_ntlmssp_final_packet' do
        let(:response) {
          packet = RubySMB::SMB2::Packet::SessionSetupResponse.new
          packet.smb2_header.nt_status = 0x00000000
          packet
        }
        let(:wrong_command) {
          packet = RubySMB::SMB2::Packet::SessionSetupResponse.new
          packet.smb2_header.nt_status = 0x00000000
          packet.smb2_header.command = RubySMB::SMB2::Commands::NEGOTIATE
          packet
        }
        it 'returns the packet object' do
          expect(smb2_client.smb2_ntlmssp_final_packet(response.to_binary_s)).to eq response
        end

        it 'raises an InvalidPacket if the Command field is wrong' do
          expect{ smb2_client.smb2_ntlmssp_final_packet(wrong_command.to_binary_s) }.to raise_error(RubySMB::Error::InvalidPacket)
        end
      end
    end
  end

  context 'Signing' do
    describe '#smb2_sign' do
      let(:request1) { RubySMB::SMB2::Packet::SessionSetupRequest.new }
      let(:fake_hmac) { "\x31\x07\x78\x3e\x35\xd7\x0e\x89\x08\x43\x8a\x18\xcd\x78\x52\x39".force_encoding("ASCII-8BIT") }

      context 'if signing is required and we have a session key' do
        it 'generates the HMAC based on the packet and the NTLM session key and signs the packet with it' do
          smb2_client.session_key = 'foo'
          smb2_client.signing_required = true
          expect(OpenSSL::HMAC).to receive(:digest).with(instance_of(OpenSSL::Digest::SHA256),smb2_client.session_key,request1.to_binary_s).and_return(fake_hmac)
          expect(smb2_client.smb2_sign(request1).smb2_header.signature).to eq fake_hmac
        end
      end

      context 'when signing is not required' do
        it 'returns the packet exactly as it was given' do
          smb2_client.session_key = 'foo'
          smb2_client.signing_required = false
          expect(smb2_client.smb2_sign(request1)).to eq request1
        end
      end

      context 'when there is no session_key' do
        it 'returns the packet exactly as it was given' do
          smb2_client.session_key = ''
          smb2_client.signing_required = true
          expect(smb2_client.smb2_sign(request1)).to eq request1
        end
      end

    end

    describe '#smb1_sign' do
      let(:request1) { RubySMB::SMB1::Packet::SessionSetupRequest.new }
      let(:fake_sig) { "\x9f\x62\xcf\x08\xd9\xc2\x83\x21".force_encoding("ASCII-8BIT") }

      context 'if signing is required and we have a session key' do
        it 'generates the signature based on the packet, the sequence counter and the NTLM session key and signs the packet with it' do
          smb1_client.session_key = 'foo'
          smb1_client.signing_required = true
          raw = request1.to_binary_s
          adjusted_request = RubySMB::SMB1::Packet::SessionSetupRequest.read(raw)
          adjusted_request.smb_header.security_features = smb1_client.sequence_counter
          expect(OpenSSL::Digest::MD5).to receive(:digest).with(smb1_client.session_key + adjusted_request.to_binary_s).and_return(fake_sig)
          expect(smb1_client.smb1_sign(request1).smb_header.security_features).to eq fake_sig
        end
      end

      context 'when signing is not required' do
        it 'returns the packet exactly as it was given' do
          smb1_client.session_key = 'foo'
          smb1_client.signing_required = false
          expect(smb1_client.smb1_sign(request1)).to eq request1
        end
      end

      context 'when there is no session_key' do
        it 'returns the packet exactly as it was given' do
          smb1_client.session_key = ''
          smb1_client.signing_required = true
          expect(smb1_client.smb1_sign(request1)).to eq request1
        end
       end
    end
  end

end