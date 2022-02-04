RSpec.describe RubySMB::Dcerpc::PrintSystem::RpcAddPrinterDriverExRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :p_name }
  it { is_expected.to respond_to :p_driver_container }
  it { is_expected.to respond_to :dw_file_copy_flags }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#p_name' do
    it 'is a NdrWideStringzPtr' do
      expect(packet.p_name).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringzPtr
    end
  end

  describe '#p_driver_container' do
    it 'is a DriverContainer structure' do
      expect(packet.p_driver_container).to be_a RubySMB::Dcerpc::PrintSystem::DriverContainer
    end
  end

  describe '#dw_file_copy_flags' do
    it 'is a NdrUint32' do
      expect(packet.dw_file_copy_flags).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to RPC_ADD_PRINTER_DRIVER_EX constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::PrintSystem::RPC_ADD_PRINTER_DRIVER_EX)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      p_name: 'p_name',
      p_driver_container: RubySMB::Dcerpc::PrintSystem::DriverContainer.new(
        RubySMB::Dcerpc::PrintSystem::DriverContainer.new(
          level: 2,
          tag: 2,
          driver_info: RubySMB::Dcerpc::PrintSystem::DriverInfo2.new(
            c_version: 0,
            p_name: 'p_name',
            p_environment: 'p_environment',
            p_driver_path: 'p_driver_path',
            p_data_file: 'p_data_file',
            p_config_file: 'p_config_file'
          )
        )
      ),
      dw_file_copy_flags: 0
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

