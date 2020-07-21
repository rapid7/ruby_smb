RSpec.describe RubySMB::Dcerpc::Svcctl::OpenSCManagerWResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :lp_sc_handle }
  it { is_expected.to respond_to :error_status }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#lp_sc_handle' do
    it 'is a ScRpcHandle structure' do
      expect(packet.lp_sc_handle).to be_a RubySMB::Dcerpc::Svcctl::ScRpcHandle
    end
  end

  describe '#error_status' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.error_status).to be_a BinData::Uint32le
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to OPEN_SC_MANAGER_W constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Svcctl::OPEN_SC_MANAGER_W)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      lp_sc_handle: {context_handle_attributes: 0, context_handle_uuid: '367abb81-9844-35f1-ad32-98f038001003'},
      error_status: 3
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

