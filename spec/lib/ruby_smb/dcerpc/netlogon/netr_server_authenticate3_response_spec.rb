RSpec.describe RubySMB::Dcerpc::Netlogon::NetrServerAuthenticate3Response do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :server_credential }
  it { is_expected.to respond_to :negotiate_flags }
  it { is_expected.to respond_to :account_rid }
  it { is_expected.to respond_to :error_status }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#server_credential' do
    it 'is a NetlogonCredential structure' do
      expect(packet.server_credential).to be_a RubySMB::Dcerpc::Netlogon::NetlogonCredential
    end
  end

  describe '#negotiate_flags' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.negotiate_flags).to be_a BinData::Uint32le
    end
  end

  describe '#account_rid' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.account_rid).to be_a BinData::Uint32le
    end
  end

  describe '#error_status' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.error_status).to be_a BinData::Uint32le
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to NETR_SERVER_AUTHENTICATE3 constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Netlogon::NETR_SERVER_AUTHENTICATE3)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      server_credential: "\x00" * 8,
      negotiate_flags: rand(0xffffffff),
      account_rid: rand(0xffffffff),
      error_status: rand(0xffffffff)
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end
