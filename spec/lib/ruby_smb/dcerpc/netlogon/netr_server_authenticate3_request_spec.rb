RSpec.describe RubySMB::Dcerpc::Netlogon::NetrServerAuthenticate3Request do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :primary_name }
  it { is_expected.to respond_to :account_name }
  it { is_expected.to respond_to :secure_channel_type }
  it { is_expected.to respond_to :computer_name }
  it { is_expected.to respond_to :client_credential }
  it { is_expected.to respond_to :flags }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#primary_name' do
    it 'is a LogonsrvHandle structure' do
      expect(packet.primary_name).to be_a RubySMB::Dcerpc::Netlogon::LogonsrvHandle
    end
  end

  describe '#account_name' do
    it 'is a NdrString structure' do
      expect(packet.account_name).to be_a RubySMB::Dcerpc::Ndr::NdrString
    end
  end

  describe '#secure_channel_type' do
    it 'is a NetlogonSecureChannelType enum' do
      expect(packet.secure_channel_type).to be_a RubySMB::Dcerpc::Netlogon::NetlogonSecureChannelType
    end
  end

  describe '#computer_name' do
    it 'is a NdrString structure' do
      expect(packet.computer_name).to be_a RubySMB::Dcerpc::Ndr::NdrString
    end
  end

  describe '#client_credential' do
    it 'is a NetlogonCredential structure' do
      expect(packet.client_credential).to be_a RubySMB::Dcerpc::Netlogon::NetlogonCredential
    end
  end

  describe '#flags' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.flags).to be_a BinData::Uint32le
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to NETR_SERVER_AUTHENTICATE3 constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Netlogon::NETR_SERVER_AUTHENTICATE3)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      primary_name: 'primary_name',
      account_name: 'account_name',
      secure_channel_type: 0,
      computer_name: 'computer_name',
      client_credential: "\x00" * 8,
      flags: rand(0xffffffff)
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end
