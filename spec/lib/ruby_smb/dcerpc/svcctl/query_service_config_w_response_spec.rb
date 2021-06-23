RSpec.describe RubySMB::Dcerpc::Svcctl::LpBoundedDword8k do
  subject(:packet) { described_class.new }

  it 'is BinData::Uint32le subclass' do
    expect(described_class).to be < BinData::Uint32le
  end
end

RSpec.describe RubySMB::Dcerpc::Svcctl::QueryServiceConfigW do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :dw_service_type }
  it { is_expected.to respond_to :dw_start_type }
  it { is_expected.to respond_to :dw_error_control }
  it { is_expected.to respond_to :lp_binary_path_name }
  it { is_expected.to respond_to :lp_load_order_group }
  it { is_expected.to respond_to :dw_tag_id }
  it { is_expected.to respond_to :lp_dependencies }
  it { is_expected.to respond_to :lp_service_start_name }
  it { is_expected.to respond_to :lp_display_name }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#dw_service_type' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.dw_service_type).to be_a BinData::Uint32le
    end
  end

  describe '#dw_start_type' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.dw_start_type).to be_a BinData::Uint32le
    end
  end

  describe '#dw_error_control' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.dw_error_control).to be_a BinData::Uint32le
    end
  end

  describe '#lp_binary_path_name' do
    it 'is a NdrWideStringPtr structure' do
      expect(packet.lp_binary_path_name).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringPtr
    end
  end

  describe '#lp_load_order_group' do
    it 'is a NdrWideStringPtr structure' do
      expect(packet.lp_load_order_group).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringPtr
    end
  end

  describe '#dw_tag_id' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.dw_tag_id).to be_a BinData::Uint32le
    end
  end

  describe '#lp_dependencies' do
    it 'is a NdrWideStringPtr structure' do
      expect(packet.lp_dependencies).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringPtr
    end
  end

  describe '#lp_service_start_name' do
    it 'is a NdrWideStringPtr structure' do
      expect(packet.lp_service_start_name).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringPtr
    end
  end

  describe '#lp_display_name' do
    it 'is a NdrWideStringPtr structure' do
      expect(packet.lp_display_name).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringPtr
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      dw_service_type: 3,
      dw_start_type: 4,
      dw_error_control: 5,
      lp_binary_path_name: 'test',
      lp_load_order_group: 'test2',
      dw_tag_id: 3,
      lp_dependencies: 'test3',
      lp_service_start_name: 'test4',
      lp_display_name: 'test5'
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

RSpec.describe RubySMB::Dcerpc::Svcctl::QueryServiceConfigWResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :lp_service_config }
  it { is_expected.to respond_to :pcb_bytes_needed }
  it { is_expected.to respond_to :error_status }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#lp_service_config' do
    it 'is a QueryServiceConfigW structure' do
      expect(packet.lp_service_config).to be_a RubySMB::Dcerpc::Svcctl::QueryServiceConfigW
    end
  end

  describe '#pcb_bytes_needed' do
    it 'is a LpBoundedDword8k structure' do
      expect(packet.pcb_bytes_needed).to be_a RubySMB::Dcerpc::Svcctl::LpBoundedDword8k
    end
  end

  describe '#error_status' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.error_status).to be_a BinData::Uint32le
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to QUERY_SERVICE_CONFIG_W constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Svcctl::QUERY_SERVICE_CONFIG_W)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    sc = RubySMB::Dcerpc::Svcctl::QueryServiceConfigW.new(
      dw_service_type: 3,
      dw_start_type: 4,
      dw_error_control: 5,
      lp_binary_path_name: 'test',
      lp_load_order_group: 'test2',
      dw_tag_id: 3,
      lp_dependencies: 'test3',
      lp_service_start_name: 'test4',
      lp_display_name: 'test5'
    )
    packet = described_class.new(
      lp_service_config: sc,
      pcb_bytes_needed: 4,
      error_status: 3
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end
