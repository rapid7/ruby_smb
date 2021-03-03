RSpec.describe RubySMB::Dcerpc::Netlogon::NetrServerReqChallengeRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :primary_name }
  it { is_expected.to respond_to :computer_name }
  it { is_expected.to respond_to :client_challenge }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#primary_name' do
    it 'is a LogonsrvHandle structure' do
      expect(packet.primary_name).to be_a RubySMB::Dcerpc::Netlogon::LogonsrvHandle
    end
  end

  describe '#computer_name' do
    it 'is a ConfVarWideString structure' do
      expect(packet.computer_name).to be_a RubySMB::Dcerpc::Ndr::ConfVarWideString
    end
  end

  describe '#client_challenge' do
    it 'is a NetlogonCredential structure' do
      expect(packet.client_challenge).to be_a RubySMB::Dcerpc::Netlogon::NetlogonCredential
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to NETR_SERVER_REQ_CHALLENGE constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Netlogon::NETR_SERVER_REQ_CHALLENGE)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      primary_name: 'primary_name',
      computer_name: 'computer_name',
      client_challenge: "\x00" * 8,
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end
