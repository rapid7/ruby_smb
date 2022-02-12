RSpec.describe RubySMB::Dcerpc::Svcctl::CreateServiceWRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :h_sc_object }
  it { is_expected.to respond_to :lp_service_name }
  it { is_expected.to respond_to :lp_display_name }
  it { is_expected.to respond_to :dw_desired_access }
  it { is_expected.to respond_to :dw_service_type }
  it { is_expected.to respond_to :dw_start_type }
  it { is_expected.to respond_to :dw_error_control }
  it { is_expected.to respond_to :lp_binary_path_name }
  it { is_expected.to respond_to :lp_load_order_group }
  it { is_expected.to respond_to :lp_dw_tag_id }
  it { is_expected.to respond_to :lp_dependencies }
  it { is_expected.to respond_to :dw_depend_size }
  it { is_expected.to respond_to :lp_service_start_name }
  it { is_expected.to respond_to :lp_password }
  it { is_expected.to respond_to :dw_pw_size }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end


  describe '#h_sc_object' do
    it 'is a ScRpcHandle structure' do
      expect(packet.h_sc_object).to be_a RubySMB::Dcerpc::Svcctl::ScRpcHandle
    end
  end

  describe '#lp_service_name' do
    it 'is a NdrConfVarWideStringz structure' do
      expect(packet.lp_service_name).to be_a RubySMB::Dcerpc::Ndr::NdrConfVarWideStringz
    end
  end

  describe '#lp_display_name' do
    it 'is a NdrWideStringzPtr structure' do
      expect(packet.lp_display_name).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringzPtr
    end
  end

  describe '#dw_desired_access' do
    it 'is a NdrUint32' do
      expect(packet.dw_desired_access).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#dw_service_type' do
    it 'is a NdrUint32' do
      expect(packet.dw_service_type).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#dw_start_type' do
    it 'is a NdrUint32' do
      expect(packet.dw_start_type).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#dw_error_control' do
    it 'is a NdrUint32' do
      expect(packet.dw_error_control).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#lp_binary_path_name' do
    it 'is a NdrConfVarWideStringz structure' do
      expect(packet.lp_binary_path_name).to be_a RubySMB::Dcerpc::Ndr::NdrConfVarWideStringz
    end
  end

  describe '#lp_load_order_group' do
    it 'is a NdrWideStringzPtr structure' do
      expect(packet.lp_load_order_group).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringzPtr
    end
  end

  describe '#lp_dw_tag_id' do
    it 'is a NdrUint32Ptr' do
      expect(packet.lp_dw_tag_id).to be_a RubySMB::Dcerpc::Ndr::NdrUint32Ptr
    end
  end

  describe '#lp_dependencies' do
    it 'is a SvcctlByteArrayPtr structure' do
      expect(packet.lp_dependencies).to be_a RubySMB::Dcerpc::Svcctl::SvcctlByteArrayPtr
    end
  end

  describe '#dw_depend_size' do
    it 'is a NdrUint32' do
      expect(packet.dw_depend_size).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#lp_service_start_name' do
    it 'is a NdrWideStringzPtr structure' do
      expect(packet.lp_service_start_name).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringzPtr
    end
  end

  describe '#lp_password' do
    it 'is a SvcctlByteArrayPtr structure' do
      expect(packet.lp_password).to be_a RubySMB::Dcerpc::Svcctl::SvcctlByteArrayPtr
    end
  end

  describe '#dw_pw_size' do
    it 'is a NdrUint32' do
      expect(packet.dw_pw_size).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  it 'should keep #dw_desired_access 4-byte aligned' do
    5.times do |i1|
      5.times do |i2|
        packet.lp_service_name = "A" * i1
        packet.lp_display_name = "B" * i2
        expect(packet.dw_desired_access.abs_offset % 4).to eq 0
      end
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to CREATE_SERVICE_W constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Svcctl::CREATE_SERVICE_W)
    end
  end

  it 'reads its own binary representation and outputs the same packet' do
    packet = described_class.new(
      h_sc_object: {context_handle_attributes: 0, context_handle_uuid: '367abb81-9844-35f1-ad32-98f038001003'},
      lp_service_name: 'test',
      lp_display_name: 'Test',
      dw_desired_access: 3,
      lp_binary_path_name: 'test',
      lp_password: 'test'.bytes
    )
    binary = packet.to_binary_s
    expect(described_class.read(binary)).to eq(packet)
  end
end
