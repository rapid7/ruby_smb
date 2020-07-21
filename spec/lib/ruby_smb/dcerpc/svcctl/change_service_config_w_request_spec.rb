RSpec.describe RubySMB::Dcerpc::Svcctl::ChangeServiceConfigWRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :h_service }
  it { is_expected.to respond_to :dw_service_type }
  it { is_expected.to respond_to :dw_start_type }
  it { is_expected.to respond_to :dw_error_control }
  it { is_expected.to respond_to :lp_binary_path_name }
  it { is_expected.to respond_to :pad1 }
  it { is_expected.to respond_to :lp_load_order_group }
  it { is_expected.to respond_to :pad2 }
  it { is_expected.to respond_to :dw_tag_id }
  it { is_expected.to respond_to :lp_dependencies }
  it { is_expected.to respond_to :pad3 }
  it { is_expected.to respond_to :dw_depend_size }
  it { is_expected.to respond_to :lp_service_start_name }
  it { is_expected.to respond_to :pad4 }
  it { is_expected.to respond_to :lp_password }
  it { is_expected.to respond_to :pad5 }
  it { is_expected.to respond_to :dw_pw_size }
  it { is_expected.to respond_to :lp_display_name }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#h_service' do
    it 'is a ScRpcHandle structure' do
      expect(packet.h_service).to be_a RubySMB::Dcerpc::Svcctl::ScRpcHandle
    end
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

  describe '#dw_start_type' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.dw_start_type).to be_a BinData::Uint32le
    end
  end

  describe '#lp_binary_path_name' do
    it 'is a NdrLpStr structure' do
      expect(packet.lp_binary_path_name).to be_a RubySMB::Dcerpc::Ndr::NdrLpStr
    end
  end

  describe '#pad1' do
    it 'is a string' do
      expect(packet.pad1).to be_a BinData::String
    end

    it 'should keep #lp_load_order_group 4-byte aligned' do
      packet.lp_binary_path_name = "test"
      expect(packet.lp_load_order_group.abs_offset % 4).to eq 0
    end
  end

  describe '#lp_load_order_group' do
    it 'is a NdrLpStr structure' do
      expect(packet.lp_load_order_group).to be_a RubySMB::Dcerpc::Ndr::NdrLpStr
    end
  end

  describe '#pad2' do
    it 'is a string' do
      expect(packet.pad1).to be_a BinData::String
    end

    it 'should keep #dw_tag_id 4-byte aligned' do
      packet.lp_load_order_group = "test"
      expect(packet.dw_tag_id.abs_offset % 4).to eq 0
    end
  end

  describe '#dw_tag_id' do
    it 'is a NdrLpDword structure' do
      expect(packet.dw_tag_id).to be_a RubySMB::Dcerpc::Ndr::NdrLpDword
    end
  end

  describe '#lp_dependencies' do
    it 'is a NdrLpByte structure' do
      expect(packet.lp_dependencies).to be_a RubySMB::Dcerpc::Ndr::NdrLpByte
    end
  end

  describe '#pad3' do
    it 'is a string' do
      expect(packet.pad1).to be_a BinData::String
    end

    it 'should keep #dw_depend_size 4-byte aligned' do
      packet.lp_dependencies = [1, 2, 3, 4]
      expect(packet.dw_depend_size.abs_offset % 4).to eq 0
    end
  end

  describe '#dw_depend_size' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.dw_depend_size).to be_a BinData::Uint32le
    end
  end

  describe '#lp_service_start_name' do
    it 'is a NdrLpStr structure' do
      expect(packet.lp_service_start_name).to be_a RubySMB::Dcerpc::Ndr::NdrLpStr
    end
  end

  describe '#pad4' do
    it 'is a string' do
      expect(packet.pad1).to be_a BinData::String
    end

    it 'should keep #lp_password 4-byte aligned' do
      packet.lp_service_start_name = "test"
      expect(packet.lp_password.abs_offset % 4).to eq 0
    end
  end

  describe '#lp_password' do
    it 'is a NdrLpByte structure' do
      expect(packet.lp_password).to be_a RubySMB::Dcerpc::Ndr::NdrLpByte
    end
  end

  describe '#pad5' do
    it 'is a string' do
      expect(packet.pad1).to be_a BinData::String
    end

    it 'should keep #dw_pw_size 4-byte aligned' do
      packet.lp_password = [1, 2, 3, 4]
      expect(packet.dw_pw_size.abs_offset % 4).to eq 0
    end
  end

  describe '#dw_pw_size' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.dw_pw_size).to be_a BinData::Uint32le
    end

    it 'has a value set to #lp_password.max_count' do
      packet.lp_password.max_count = 33
      expect(packet.dw_pw_size).to eq(33)
    end
  end

  describe '#lp_display_name' do
    it 'is a NdrLpStr structure' do
      expect(packet.lp_display_name).to be_a RubySMB::Dcerpc::Ndr::NdrLpStr
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to CHANGE_SERVICE_CONFIG_W constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Svcctl::CHANGE_SERVICE_CONFIG_W)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      h_service: {context_handle_attributes: 0, context_handle_uuid: '367abb81-9844-35f1-ad32-98f038001003'},
      dw_service_type: 33,
      dw_start_type: 3,
      dw_error_control: 11,
      lp_binary_path_name: 'test',
      lp_load_order_group: 'test2',
      dw_tag_id: 4,
      lp_dependencies: [1,2],
      dw_depend_size: 2,
      lp_service_start_name: 'test3',
      lp_password: [1,2,3],
      dw_pw_size: 3,
      lp_display_name: 'test4'
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end

