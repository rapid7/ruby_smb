RSpec.describe RubySMB::Dcerpc::Netlogon::NetrServerPasswordSet2Response do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :return_authenticator }
  it { is_expected.to respond_to :error_status }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#return_authenticator' do
    it 'is a NetlogonAuthenticator structure' do
      expect(packet.return_authenticator).to be_a RubySMB::Dcerpc::Netlogon::NetlogonAuthenticator
    end
  end

  describe '#error_status' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.error_status).to be_a BinData::Uint32le
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to NETR_SERVER_PASSWORD_SET2 constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Netlogon::NETR_SERVER_PASSWORD_SET2)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      return_authenticator: RubySMB::Dcerpc::Netlogon::NetlogonAuthenticator.new,
      error_status: rand(0xffffffff)
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end
