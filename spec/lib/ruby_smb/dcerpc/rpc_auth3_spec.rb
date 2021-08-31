RSpec.describe RubySMB::Dcerpc::RpcAuth3 do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :pdu_header }
  it { is_expected.to respond_to :pad }
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

    it 'should have the #ptype field set to PTypes::BIND' do
      expect(header.ptype).to eq RubySMB::Dcerpc::PTypes::RPC_AUTH3
    end
  end

  describe '#sec_trailer' do
    it 'should be SecTrailer structure' do
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

  it 'reads its own binary representation and output the same packet' do
    auth_size = rand(0xFF)
    packet = described_class.new(
      pdu_header: { auth_length: auth_size },
      pad: rand(0xFFFFFFFF),
      auth_value: 'A' * auth_size
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end

end
