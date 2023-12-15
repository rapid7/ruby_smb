RSpec.describe RubySMB::Dcerpc::Efsrpc::EfsRpcEncryptFileSrvRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :file_name }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#file_name' do
    it 'is a NdrConfVarWideStringz' do
      expect(packet.file_name).to be_a RubySMB::Dcerpc::Ndr::NdrConfVarWideStringz
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to EFS_RPC_ENCRYPT_FILE_SRV constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Efsrpc::EFS_RPC_ENCRYPT_FILE_SRV)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      file_name: 'file_name'
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

