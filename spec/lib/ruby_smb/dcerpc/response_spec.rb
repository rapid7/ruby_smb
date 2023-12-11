RSpec.describe RubySMB::Dcerpc::Response do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :pdu_header }
  it { is_expected.to respond_to :alloc_hint }
  it { is_expected.to respond_to :p_cont_id }
  it { is_expected.to respond_to :cancel_count }
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

    it 'should have the #ptype field set to PTypes::RESPONSE' do
      expect(header.ptype).to eq RubySMB::Dcerpc::PTypes::RESPONSE
    end
  end

  describe '#alloc_hint' do
    it 'should be a 32-bit unsigned integer' do
      expect(packet.alloc_hint).to be_a BinData::Uint32le
    end

    it 'should be the size of the #stub field' do
      stub = 'ABCD'
      packet.stub = stub
      expect(packet.alloc_hint).to eq(stub.length)
    end
  end

  describe '#p_cont_id' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.p_cont_id).to be_a BinData::Uint16le
    end
  end

  describe '#cancel_count' do
    it 'should be a 8-bit unsigned integer' do
      expect(packet.cancel_count).to be_a BinData::Uint8
    end
  end

  describe '#stub' do
    it 'is a string' do
      expect(packet.stub).to be_a BinData::String
    end

    it 'reads the expected number of bytes' do
      stub = 'ABCDEFGH'
      packet.pdu_header.frag_length = 28
      packet.stub.read(stub)
      expect(packet.stub).to eq(stub[0,4])
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

  describe '#stub_length' do
    let(:stub_length) { rand(1..0xFF) }
    before :example do
      packet.stub = 'A' * stub_length
    end

    it 'returns the correct stub length' do
      expect(packet.stub_length).to eq(stub_length)
    end

    context 'with auth verifier' do
      it 'returns the correct stub length' do
        auth_size = rand(1..0xFF)
        packet.pdu_header.auth_length = auth_size
        packet.auth_value = 'B' * auth_size
        expect(packet.stub_length).to eq(stub_length + packet.auth_pad.num_bytes)
      end
    end
  end

  describe '#read' do
    let(:response) { described_class.new }
    let(:auth_size) { rand(1..0xFF) }
    let(:stub_size) { rand(1..0xFF) }
    before :example do
      response.pdu_header.auth_length = auth_size
      response.stub = 'A' * stub_size
      response.auth_value = 'B' * auth_size
      response.auth_pad = 'C' * response.auth_pad.size
    end

    it 'sets #stub and #auth_pad to the correct values' do
      packet.read(response.to_binary_s)
      expect(packet.stub).to eq(response.stub)
      expect(packet.auth_pad).to eq(response.auth_pad)
    end
  end

  it 'reads its own binary representation and output the same packet' do
    packet.stub = 'ABCD'
    packet.auth_value = '123456'
    packet.pdu_header.auth_length = 6
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end
