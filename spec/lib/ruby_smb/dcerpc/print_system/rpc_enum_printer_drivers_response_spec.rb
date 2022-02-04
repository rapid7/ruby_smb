RSpec.describe RubySMB::Dcerpc::PrintSystem::RpcEnumPrinterDriversResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :p_drivers }
  it { is_expected.to respond_to :pcb_needed }
  it { is_expected.to respond_to :pc_returned }
  it { is_expected.to respond_to :error_status }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#p_drivers' do
    it 'is a RprnByteArrayPtr' do
      expect(packet.p_drivers).to be_a RubySMB::Dcerpc::PrintSystem::RprnByteArrayPtr
    end
  end

  describe '#pcb_needed' do
    it 'is a NdrUint32' do
      expect(packet.pcb_needed).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#pc_returned' do
    it 'is a NdrUint32' do
      expect(packet.pc_returned).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#error_status' do
    it 'is a NdrUint32' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to RPC_ENUM_PRINTER_DRIVERS constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::PrintSystem::RPC_ENUM_PRINTER_DRIVERS)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      p_drivers: [0, 1, 2],
      pcb_needed: 0,
      pc_returned: 0,
      error_status: 0
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

