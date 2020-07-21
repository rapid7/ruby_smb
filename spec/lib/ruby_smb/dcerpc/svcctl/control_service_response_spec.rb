RSpec.describe RubySMB::Dcerpc::Svcctl::ControlServiceResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :lp_service_status }
  it { is_expected.to respond_to :error_status }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#lp_service_status' do
    it 'is a ServiceStatus structure' do
      expect(packet.lp_service_status).to be_a RubySMB::Dcerpc::Svcctl::ServiceStatus
    end
  end

  describe '#error_status' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.error_status).to be_a BinData::Uint32le
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to CONTROL_SERVICE constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Svcctl::CONTROL_SERVICE)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      service_status: RubySMB::Dcerpc::Svcctl::ServiceStatus.new(dw_service_type: 8, dw_current_state:2, dw_controls_accepted:1),
      error_status: 3
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

