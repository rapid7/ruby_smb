RSpec.describe RubySMB::Dcerpc::Svcctl::ChangeServiceConfigWResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :dw_tag_id }
  it { is_expected.to respond_to :error_status }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#dw_tag_id' do
    it 'is a NdrUint32Ptr structure' do
      expect(packet.dw_tag_id).to be_a RubySMB::Dcerpc::Ndr::NdrUint32Ptr
    end
  end

  describe '#error_status' do
    it 'is a NdrUint32' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to CHANGE_SERVICE_CONFIG_W constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Svcctl::CHANGE_SERVICE_CONFIG_W)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      dw_tag_id: 4,
      error_status: 1
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

