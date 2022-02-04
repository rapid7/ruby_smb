RSpec.describe RubySMB::Dcerpc::PrintSystem::RpcGetPrinterDriverDirectoryResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :p_driver_directory }
  it { is_expected.to respond_to :pcb_needed }
  it { is_expected.to respond_to :error_status }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#p_driver_directory' do
    it 'is a RprnByteArrayPtr' do
      expect(packet.p_driver_directory).to be_a RubySMB::Dcerpc::PrintSystem::RprnByteArrayPtr
    end
  end

  describe '#pcb_needed' do
    it 'is a NdrUint32' do
      expect(packet.pcb_needed).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#error_status' do
    it 'is a NdrUint32' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to RPC_GET_PRINTER_DRIVER_DIRECTORY constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::PrintSystem::RPC_GET_PRINTER_DRIVER_DIRECTORY)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      p_driver_directory: [0, 1, 2],
      pcb_needed: 0,
      error_status: 0
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

