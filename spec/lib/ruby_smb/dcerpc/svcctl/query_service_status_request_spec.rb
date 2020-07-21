RSpec.describe RubySMB::Dcerpc::Svcctl::QueryServiceStatusRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :h_service }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#h_service' do
    it 'is a ScRpcHandle structure' do
      expect(packet.h_service).to be_a RubySMB::Dcerpc::Svcctl::ScRpcHandle
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to QUERY_SERVICE_STATUS constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Svcctl::QUERY_SERVICE_STATUS)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      h_service: {context_handle_attributes: 0, context_handle_uuid: '367abb81-9844-35f1-ad32-98f038001003'}
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

