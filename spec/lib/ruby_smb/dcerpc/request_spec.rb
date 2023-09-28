RSpec.describe RubySMB::Dcerpc::Request do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :pdu_header }
  it { is_expected.to respond_to :alloc_hint }
  it { is_expected.to respond_to :p_cont_id }
  it { is_expected.to respond_to :opnum }
  it { is_expected.to respond_to :object }
  it { is_expected.to respond_to :stub }
  it { is_expected.to respond_to :auth_pad }
  it { is_expected.to respond_to :sec_trailer }
  it { is_expected.to respond_to :auth_value }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#pdu_header' do
    subject(:header) { packet.pdu_header }

    it 'is a standard PDU Header' do
      expect(header).to be_a RubySMB::Dcerpc::PDUHeader
    end

    it 'should have the #ptype field set to PTypes::BIND_ACK' do
      expect(header.ptype).to eq RubySMB::Dcerpc::PTypes::REQUEST
    end
  end

  describe '#alloc_hint' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.alloc_hint).to be_a BinData::Uint32le
    end

    it 'should be the size of the #stub field' do
      packet = described_class.new({ :opnum => RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL }, host: '1.2.3.4')
      expect(packet.alloc_hint).to eq(packet.stub.do_num_bytes)
    end
  end

  describe '#p_cont_id' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.p_cont_id).to be_a BinData::Uint16le
    end
  end

  describe '#opnum' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.opnum).to be_a BinData::Uint16le
    end
  end

  describe '#object' do
    it 'is a Uuid' do
      expect(packet.object).to be_a RubySMB::Dcerpc::Uuid
    end

    it 'only exists if #object_uuid header flag is set' do
      packet.pdu_header.pfc_flags.object_uuid = 1
      expect(packet.object?).to be true
    end

    it 'does not  exist if #object_uuid header flag is not set' do
      packet.pdu_header.pfc_flags.object_uuid = 0
      expect(packet.object?).to be false
    end
  end

  describe '#stub' do
    it 'is a Bindata Choice' do
      expect(packet.stub).to be_a BinData::Choice
    end

    context 'with a Srvsvc endpoint' do
      let(:host) { '1.2.3.4' }
      let(:packet) do
        described_class.new(
          { :opnum => RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL },
          { :endpoint => 'Srvsvc', :host => host }
        )
      end

      it 'uses endpoint parameter to select a Srvsvc stub packet' do
        expect(packet.stub.selection).to eq('Srvsvc')
      end

      it 'selects the expected packet structure' do
        expect(packet.stub).to eq(RubySMB::Dcerpc::Srvsvc::NetShareEnumAllRequest.new)
      end
    end

    context 'with a Winreg endpoint' do
      let(:opnum) { RubySMB::Dcerpc::Winreg::OPEN_HKCR }
      let(:packet) do
        described_class.new(
          { :opnum => opnum },
          { :endpoint => 'Winreg' }
        )
      end

      it 'uses endpoint parameter to select a Winreg stub packet' do
        expect(packet.stub.selection).to eq('Winreg')
      end

      it 'selects the expected packet structure' do
        expect(packet.stub).to eq(RubySMB::Dcerpc::Winreg::OpenRootKeyRequest.new(opnum: opnum))
      end
    end

    context 'with an unknown endpoint' do
      let(:packet) do
        described_class.new(
          { :endpoint => 'Unknown' }
        )
      end

      it 'sets #stub to an empty string' do
        expect(packet.stub).to eq('')
      end
    end
  end

  describe '#auth_pad' do
    it 'should be a string' do
      expect(packet.auth_pad).to be_a BinData::String
    end

    it 'should not exist if the #auth_length PDU header field is 0' do
      packet.pdu_header.auth_length = 0
      expect(packet.auth_pad?).to be false
    end

    it 'should exist only if the #auth_length PDU header field is greater than 0' do
      packet.pdu_header.auth_length = 10
      expect(packet.auth_pad?).to be true
    end
  end

  describe '#sec_trailer' do
    it 'is a SecTrailer structre' do
      expect(packet.sec_trailer).to be_a RubySMB::Dcerpc::SecTrailer
    end

    it 'should not exist if the #auth_length PDU header field is 0' do
      packet.pdu_header.auth_length = 0
      expect(packet.sec_trailer?).to be false
    end

    it 'should exist only if the #auth_length PDU header field is greater than 0' do
      packet.pdu_header.auth_length = 10
      expect(packet.sec_trailer?).to be true
    end
  end

  describe '#auth_value' do
    it 'should be a string' do
      expect(packet.auth_value).to be_a BinData::String
    end

    it 'should not exist if the #auth_length PDU header field is 0' do
      packet.pdu_header.auth_length = 0
      expect(packet.auth_value?).to be false
    end

    it 'should exist only if the #auth_length PDU header field is greater than 0' do
      packet.pdu_header.auth_length = 10
      expect(packet.auth_value?).to be true
    end

    it 'reads #auth_length bytes' do
      auth_value = '12345678'
      packet.pdu_header.auth_length = 6
      packet.auth_value.read(auth_value)
      expect(packet.auth_value).to eq(auth_value[0,6])
    end
  end

  describe '#enable_encrypted_stub' do
    it 'sets the stub type to BinData::String' do
      # Set a new packet with a Winreg stub
      packet = described_class.new(
        { opnum: RubySMB::Dcerpc::Winreg::OPEN_HKPD },
        { endpoint: 'Winreg' }
      )
      # Enabling encryption will switch the stub to a string
      packet.enable_encrypted_stub
      expect(packet.stub.send(:current_choice)).to be_a BinData::String
    end
  end

  describe '#has_auth_verifier?' do
    it 'returns true if PDU header #auth_length is greater than 0' do
      packet.pdu_header.auth_length = 5
      expect(packet.has_auth_verifier?).to be true
    end

    it 'returns false if PDU header #auth_length is 0' do
      packet.pdu_header.auth_length = 0
      expect(packet.has_auth_verifier?).to be false
    end
  end

  it 'reads its own binary representation and output the same packet' do
    packet = described_class.new(
      { :opnum => RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL },
      { :endpoint => 'Srvsvc' }
    )
    packet.pdu_header.pfc_flags.object_uuid = 1
    packet.object = '8a885d04-1ceb-11c9-9fe8-08002b104860'
    packet.auth_value = '123456'
    packet.pdu_header.auth_length = 6
    binary = packet.to_binary_s
    packet2 = described_class.new( { :endpoint => 'Srvsvc' } )
    expect(packet2.read(binary)).to eq(packet)
  end
end
