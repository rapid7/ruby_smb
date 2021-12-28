RSpec.describe RubySMB::Dcerpc::Netlogon::NetrServerPasswordSet2Request do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :primary_name }
  it { is_expected.to respond_to :account_name }
  it { is_expected.to respond_to :secure_channel_type }
  it { is_expected.to respond_to :computer_name }
  it { is_expected.to respond_to :authenticator }
  it { is_expected.to respond_to :clear_new_password }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#primary_name' do
    it 'is a LogonsrvHandle structure' do
      expect(packet.primary_name).to be_a RubySMB::Dcerpc::Netlogon::LogonsrvHandle
    end
  end

  describe '#account_name' do
    it 'is a NdrConfVarWideStringz structure' do
      expect(packet.account_name).to be_a RubySMB::Dcerpc::Ndr::NdrConfVarWideStringz
    end
  end

  describe '#secure_channel_type' do
    it 'is a NetlogonSecureChannelType enum' do
      expect(packet.secure_channel_type).to be_a RubySMB::Dcerpc::Netlogon::NetlogonSecureChannelType
    end
  end

  describe '#computer_name' do
    it 'is a NdrConfVarWideStringz structure' do
      expect(packet.computer_name).to be_a RubySMB::Dcerpc::Ndr::NdrConfVarWideStringz
    end
  end

  describe '#authenticator' do
    it 'is a NetlogonAuthenticator structure' do
      expect(packet.authenticator).to be_a RubySMB::Dcerpc::Netlogon::NetlogonAuthenticator
    end
  end

  describe '#clear_new_password' do
    it 'is a NdrFixedByteArray structure' do
      expect(packet.clear_new_password).to be_a RubySMB::Dcerpc::Ndr::NdrFixedByteArray
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to NETR_SERVER_PASSWORD_SET2 constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Netlogon::NETR_SERVER_PASSWORD_SET2)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      primary_name: 'primary_name',
      account_name: 'account_name',
      secure_channel_type: 0,
      computer_name: 'computer_name',
      authenticator: RubySMB::Dcerpc::Netlogon::NetlogonAuthenticator.new,
      clear_new_password: "\x00" * 516
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end
