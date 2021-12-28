RSpec.describe RubySMB::Dcerpc::Netlogon::NetrServerReqChallengeResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :server_challenge }
  it { is_expected.to respond_to :error_status }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#server_challenge' do
    it 'is a NetlogonCredential structure' do
      expect(packet.server_challenge).to be_a RubySMB::Dcerpc::Netlogon::NetlogonCredential
    end
  end

  describe '#error_status' do
    it 'is a NDR 32-bit unsigned integer' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to NETR_SERVER_REQ_CHALLENGE constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Netlogon::NETR_SERVER_REQ_CHALLENGE)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      server_challenge: "\x00" * 8,
      error_status: rand(0xffffffff)
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end
