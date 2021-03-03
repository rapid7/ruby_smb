RSpec.describe RubySMB::Dcerpc::Svcctl::SvcctlHandleW do
  subject(:packet) { described_class.new }

  it 'is Ndr::WideStringPtr subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::WideStringPtr
  end
end

RSpec.describe RubySMB::Dcerpc::Svcctl::OpenSCManagerWRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :lp_machine_name }
  it { is_expected.to respond_to :pad1 }
  it { is_expected.to respond_to :lp_database_name }
  it { is_expected.to respond_to :pad2 }
  it { is_expected.to respond_to :dw_desired_access }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#lp_machine_name' do
    it 'is a SvcctlHandleW structure' do
      expect(packet.lp_machine_name).to be_a RubySMB::Dcerpc::Svcctl::SvcctlHandleW
    end
  end

  describe '#pad1' do
    it 'is a string' do
      expect(packet.pad1).to be_a BinData::String
    end

    it 'should keep #lp_database_name 4-byte aligned' do
      packet.lp_machine_name = "test"
      expect(packet.lp_database_name.abs_offset % 4).to eq 0
    end
  end

  describe '#lp_database_name' do
    it 'is a Ndr::WideStringPtr structure' do
      expect(packet.lp_database_name).to be_a RubySMB::Dcerpc::Ndr::WideStringPtr
    end
  end

  describe '#pad2' do
    it 'is a string' do
      expect(packet.pad1).to be_a BinData::String
    end

    it 'should keep #dw_desired_access 4-byte aligned' do
      packet.lp_database_name = "test"
      expect(packet.dw_desired_access.abs_offset % 4).to eq 0
    end
  end

  describe '#dw_desired_access' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.dw_desired_access).to be_a BinData::Uint32le
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to OPEN_SC_MANAGER_W constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Svcctl::OPEN_SC_MANAGER_W)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      lp_machine_name: 'test',
      lp_database_name: 'test2',
      dw_desired_access: 3
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

