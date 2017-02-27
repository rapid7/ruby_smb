require 'spec_helper'

RSpec.describe RubySMB::Client do

  let(:dispatcher) { RubySMB::Dispatcher::Socket.new(nil) }
  subject(:client) { described_class.new(dispatcher) }
  subject(:smb1_client) { described_class.new(dispatcher, smb2:false) }
  subject(:smb2_client) { described_class.new(dispatcher, smb1:false) }

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
      smb_client = described_class.new(dispatcher, smb1:false)
      expect(smb_client.smb1).to be false
    end

    it 'accepts an argument to disable smb2 support' do
      expect(smb1_client.smb2).to be false
    end

    it 'raises an exception if both SMB1 and SMB2 are disabled' do
      expect{described_class.new(dispatcher, smb1:false, smb2:false)}.to raise_error(ArgumentError, 'You must enable at least one Protocol')
    end
  end

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

    it 'sets the Message ID to 1' do
      expect(client.smb2_negotiate_request.smb2_header.message_id).to eq 1
    end
  end

  describe '#negotiate_request' do
    before(:each) do
      expect(dispatcher).to receive(:send_packet).and_return(nil)
      expect(dispatcher).to receive(:recv_packet).and_return("A")
    end
    it 'calls #smb1_negotiate_request if SMB1 is enabled' do
      expect(smb1_client).to receive(:smb1_negotiate_request)
      smb1_client.negotiate_request
    end

    it 'calls #smb1_negotiate_request if both protocols are enabled' do
      expect(client).to receive(:smb1_negotiate_request)
      client.negotiate_request
    end

    it 'calls #smb2_negotiate_request if SMB2 is enabled' do
      expect(smb2_client).to receive(:smb2_negotiate_request)
      smb2_client.negotiate_request
    end

    it 'returns the raw response string from the server' do
      expect(client.negotiate_request).to eq "A"
    end
  end

  describe '#negotiate_response' do
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
      #packet.parameter_block.capabilities = smb1_capabilities
      packet
    }
    let(:smb1_extended_response_raw) {
      smb1_extended_response.to_binary_s
    }

    context 'with only SMB1' do
      it 'returns a properly formed packet' do
        expect(smb1_client.negotiate_response(smb1_extended_response_raw)).to eq smb1_extended_response
      end
    end
  end

end