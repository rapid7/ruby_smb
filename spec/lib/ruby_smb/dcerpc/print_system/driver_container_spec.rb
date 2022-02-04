RSpec.describe RubySMB::Dcerpc::PrintSystem::DriverContainer do
  subject(:struct) { described_class.new }

  it { is_expected.to respond_to :level }
  it { is_expected.to respond_to :tag }
  it { is_expected.to respond_to :driver_info }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#level' do
    it 'is a NdrUint32' do
      expect(struct.level).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#tag' do
    it 'is a NdrUint32' do
      expect(struct.tag).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  it 'reads its own binary representation and outputs the same struct' do
    struct = described_class.new(
      level: 2,
      tag: 0,
      driver_info: RubySMB::Dcerpc::PrintSystem::DriverInfo2.new(
        c_version: 0,
        p_name: 'p_name',
        p_environment: 'p_environment',
        p_driver_path: 'p_driver_path',
        p_data_file: 'p_data_file',
        p_config_file: 'p_config_file'
      )
    )
    binary = struct.to_binary_s
    expect(described_class.read(binary)).to eq(struct)
  end
end

