RSpec.describe RubySMB::Dcerpc::PrintSystem::DriverInfo2 do
  subject(:struct) { described_class.new }

  it { is_expected.to respond_to :c_version }
  it { is_expected.to respond_to :p_name }
  it { is_expected.to respond_to :p_environment }
  it { is_expected.to respond_to :p_driver_path }
  it { is_expected.to respond_to :p_data_file }
  it { is_expected.to respond_to :p_config_file }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#c_version' do
    it 'is a NdrUint32' do
      expect(struct.c_version).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#p_name' do
    it 'is a NdrWideStringzPtr' do
      expect(struct.p_name).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringzPtr
    end
  end

  describe '#p_environment' do
    it 'is a NdrWideStringzPtr' do
      expect(struct.p_environment).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringzPtr
    end
  end

  describe '#p_driver_path' do
    it 'is a NdrWideStringzPtr' do
      expect(struct.p_driver_path).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringzPtr
    end
  end

  describe '#p_data_file' do
    it 'is a NdrWideStringzPtr' do
      expect(struct.p_data_file).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringzPtr
    end
  end

  describe '#p_config_file' do
    it 'is a NdrWideStringzPtr' do
      expect(struct.p_config_file).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringzPtr
    end
  end

  it 'reads its own binary representation and outputs the same struct' do
    struct = described_class.new(
      c_version: 0,
      p_name: 'p_name',
      p_environment: 'p_environment',
      p_driver_path: 'p_driver_path',
      p_data_file: 'p_data_file',
      p_config_file: 'p_config_file'
    )
    binary = struct.to_binary_s
    expect(described_class.read(binary)).to eq(struct)
  end
end

