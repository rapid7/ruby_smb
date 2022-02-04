RSpec.describe RubySMB::Dcerpc::PrintSystem::RpcGetPrinterDriverDirectoryRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :p_name }
  it { is_expected.to respond_to :p_environment }
  it { is_expected.to respond_to :level}
  it { is_expected.to respond_to :p_driver_directory }
  it { is_expected.to respond_to :cb_buf }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#p_name' do
    it 'is a NdrWideStringzPtr' do
      expect(packet.p_name).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringzPtr
    end
  end

  describe '#p_environment' do
    it 'is a NdrWideStringzPtr' do
      expect(packet.p_environment).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringzPtr
    end
  end

  describe '#level' do
    it 'is a NdrUint32' do
      expect(packet.level).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#p_driver_directory' do
    it 'is a RprnByteArrayPtr' do
      expect(packet.p_driver_directory).to be_a RubySMB::Dcerpc::PrintSystem::RprnByteArrayPtr
    end
  end

  describe '#cb_buf' do
    it 'is a NdrUint32' do
      expect(packet.cb_buf).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to RPC_GET_PRINTER_DRIVER_DIRECTORY constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::PrintSystem::RPC_GET_PRINTER_DRIVER_DIRECTORY)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      p_name: 'p_name',
      p_environment: 'p_environment',
      level: 0,
      p_driver_directory: [0, 1, 2],
      cb_buf: 0
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

