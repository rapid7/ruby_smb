RSpec.describe RubySMB::Dcerpc::Svcctl::ServiceStatus do
  it 'is a NdrStruct' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
  end

  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :dw_service_type }
  it { is_expected.to respond_to :dw_current_state }
  it { is_expected.to respond_to :dw_controls_accepted }
  it { is_expected.to respond_to :dw_win32_exit_code }
  it { is_expected.to respond_to :dw_service_specific_exit_code }
  it { is_expected.to respond_to :dw_check_point }
  it { is_expected.to respond_to :dw_wait_hint }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#dw_service_type' do
    it 'is a NdrUint32' do
      expect(packet.dw_service_type).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#dw_current_state' do
    it 'is a NdrUint32' do
      expect(packet.dw_current_state).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#dw_controls_accepted' do
    it 'is a NdrUint32' do
      expect(packet.dw_controls_accepted).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#dw_win32_exit_code' do
    it 'is a NdrUint32' do
      expect(packet.dw_win32_exit_code).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#dw_service_specific_exit_code' do
    it 'is a NdrUint32' do
      expect(packet.dw_service_specific_exit_code).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#dw_check_point' do
    it 'is a NdrUint32' do
      expect(packet.dw_check_point).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#dw_wait_hint' do
    it 'is a NdrUint32' do
      expect(packet.dw_wait_hint).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      dw_desired_access: 2,
      dw_current_state: 3,
      dw_controls_accepted: 4,
      dw_win32_exit_code: 5,
      dw_service_specific_exit_code: 6,
      dw_check_point: 7,
      dw_wait_hint: 8
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

