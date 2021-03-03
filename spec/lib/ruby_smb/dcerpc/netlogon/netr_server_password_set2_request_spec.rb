RSpec.describe RubySMB::Dcerpc::Netlogon::NlTrustPassword do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :buffer }
  it { is_expected.to respond_to :passwd_length }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#buffer' do
    it 'is a FixArray structure' do
      expect(packet.buffer).to be_a RubySMB::Dcerpc::Ndr::FixArray
    end

    it 'is an array of wide chars' do
      expect(packet.buffer[0].class).to eq(RubySMB::Dcerpc::Ndr::WideChar)
    end

    it 'has a length of 256 elements' do
      expect(packet.buffer.length).to eq(256)
    end
  end

  describe '#passwd_length' do
    it 'is an Uint32le' do
      expect(packet.passwd_length).to be_a BinData::Uint32le
    end
  end
end

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
    it 'is a ConfVarWideString structure' do
      expect(packet.account_name).to be_a RubySMB::Dcerpc::Ndr::ConfVarWideString
    end
  end

  describe '#secure_channel_type' do
    it 'is a NetlogonSecureChannelType enum' do
      expect(packet.secure_channel_type).to be_a RubySMB::Dcerpc::Netlogon::NetlogonSecureChannelType
    end
  end

  describe '#computer_name' do
    it 'is a ConfVarWideString structure' do
      expect(packet.computer_name).to be_a RubySMB::Dcerpc::Ndr::ConfVarWideString
    end
  end

  describe '#authenticator' do
    it 'is a NetlogonAuthenticator structure' do
      expect(packet.authenticator).to be_a RubySMB::Dcerpc::Netlogon::NetlogonAuthenticator
    end
  end

  describe '#clear_new_password' do
    it 'is a NlTrustPassword structure' do
      expect(packet.clear_new_password).to be_a RubySMB::Dcerpc::Netlogon::NlTrustPassword
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
      clear_new_password: {buffer: ["\x00"] * 256, passwd_length: 0}
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end
