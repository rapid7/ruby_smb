RSpec.describe RubySMB::Dcerpc::Svcctl::CloseServiceHandleResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :h_sc_object }
  it { is_expected.to respond_to :error_status }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#h_sc_object' do
    it 'is a ScRpcHandle structure' do
      expect(packet.h_sc_object).to be_a RubySMB::Dcerpc::Svcctl::ScRpcHandle
    end
  end

  describe '#error_status' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.error_status).to be_a BinData::Uint32le
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to CLOSE_SERVICE_HANDLE constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Svcctl::CLOSE_SERVICE_HANDLE)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      h_sc_object: {context_handle_attributes: 0, context_handle_uuid: '367abb81-9844-35f1-ad32-98f038001003'},
      error_status: 3
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

