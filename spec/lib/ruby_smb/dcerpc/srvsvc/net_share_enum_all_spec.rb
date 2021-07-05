RSpec.describe RubySMB::Dcerpc::Srvsvc::NetShareEnumAllRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :server_name }
  it { is_expected.to respond_to :info_struct }
  it { is_expected.to respond_to :prefered_maximum_length }
  it { is_expected.to respond_to :resume_handle }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#server_name' do
    it 'is a SrvsvcHandle' do
      expect(packet.server_name).to be_a RubySMB::Dcerpc::Srvsvc::SrvsvcHandle
    end
  end

  describe '#info_struct' do
    it 'is a LpshareEnumStruct' do
      expect(packet.info_struct).to be_a RubySMB::Dcerpc::Srvsvc::LpshareEnumStruct
    end
  end

  describe '#prefered_maximum_length' do
    it 'is a NdrUint32' do
      expect(packet.prefered_maximum_length).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end

    it 'has a default value of 0xFFFFFFFF' do
      expect(packet.prefered_maximum_length).to eq(0xFFFFFFFF)
    end
  end

  describe '#resume_handle' do
    it 'is a NdrUint32Ptr' do
      expect(packet.resume_handle).to be_a RubySMB::Dcerpc::Ndr::NdrUint32Ptr
    end

    it 'has a default value of 0' do
      expect(packet.resume_handle).to eq(0)
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to NET_SHARE_ENUM_ALL constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL)
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Srvsvc::NetShareEnumAllResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :info_struct }
  it { is_expected.to respond_to :total_entries }
  it { is_expected.to respond_to :resume_handle }
  it { is_expected.to respond_to :error_status }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#info_struct' do
    it 'is a LpshareEnumStruct' do
      expect(packet.info_struct).to be_a RubySMB::Dcerpc::Srvsvc::LpshareEnumStruct
    end
  end

  describe '#total_entries' do
    it 'is a NdrUint32' do
      expect(packet.total_entries).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#resume_handle' do
    it 'is a NdrUint32Ptr' do
      expect(packet.resume_handle).to be_a RubySMB::Dcerpc::Ndr::NdrUint32Ptr
    end
  end

  describe '#error_status' do
    it 'is a NdrUint32' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to NET_SHARE_ENUM_ALL constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Srvsvc::NET_SHARE_ENUM_ALL)
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Srvsvc::LpshareEnumStruct do
  it 'is a NdrStruct' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
  end

  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :level }
  it { is_expected.to respond_to :switch_value }
  it { is_expected.to respond_to :share_info }

  describe '#level' do
    it 'is a NdrUint32' do
      expect(packet.level).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end

    it 'has a default value of 1' do
      expect(packet.level).to eq 1
    end
  end

  describe '#switch_value' do
    it 'is a NdrUint32' do
      expect(packet.switch_value).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end

    it 'has a default value set to the #level value' do
      expect(packet.switch_value).to eq packet.level
    end

    it 'is an hidden field' do
      expect(packet.snapshot).to_not have_key(:switch_value)
    end
  end

  describe '#share_info' do
    it 'is a BinData::Choice' do
      expect(packet.share_info).to be_a BinData::Choice
    end

    it 'selects a structure according to :level value and set the default value' do
      expect(packet.share_info.snapshot).to eq({ entries_read: 0, buffer: :null })
      # Trying to with a non existing enum value, since only Level 1 is implemented so far
      packet.level = 0
      expect { packet.share_info.snapshot }.to raise_error(IndexError)
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Srvsvc::LpshareInfo1Container do
  it 'is a ShareInfo1Container' do
    expect(described_class).to be < RubySMB::Dcerpc::Srvsvc::ShareInfo1Container
  end
  it 'is a NDR pointer' do
    expect(described_class.new).to be_a RubySMB::Dcerpc::Ndr::PointerPlugin
  end
end

RSpec.describe RubySMB::Dcerpc::Srvsvc::ShareInfo1Container do
  it 'is a NdrStruct' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
  end

  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :entries_read }
  it { is_expected.to respond_to :buffer }

  describe '#entries_read' do
    it 'is a NdrUint32' do
      expect(packet.entries_read).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#buffer' do
    it 'is a LpshareInfo1' do
      expect(packet.buffer).to be_a RubySMB::Dcerpc::Srvsvc::LpshareInfo1
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Srvsvc::LpshareInfo1 do
  it 'is a ShareInfo1' do
    expect(described_class).to be < RubySMB::Dcerpc::Srvsvc::ShareInfo1
  end
  it 'is a NDR pointer' do
    expect(described_class.new).to be_a RubySMB::Dcerpc::Ndr::PointerPlugin
  end
end

RSpec.describe RubySMB::Dcerpc::Srvsvc::ShareInfo1 do
  it 'is a NdrConfArray' do
    expect(described_class.new).to be_a RubySMB::Dcerpc::Ndr::NdrConfArray
  end
  it 'contains element of type ShareInfo1Element' do
    expect(described_class.default_parameters[:type]).to eq(:share_info1_element)
  end
end

RSpec.describe RubySMB::Dcerpc::Srvsvc::ShareInfo1Element do
  it 'is a NdrStruct' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
  end

  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :shi1_netname }
  it { is_expected.to respond_to :shi1_type }
  it { is_expected.to respond_to :shi1_remark }

  describe '#shi1_netname' do
    it 'is a NdrConfVarWideStringz' do
      expect(packet.shi1_netname).to be_a RubySMB::Dcerpc::Ndr::NdrConfVarWideStringz
    end
  end

  describe '#shi1_type' do
    it 'is a NdrUint32' do
      expect(packet.shi1_type).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe '#shi1_remark' do
    it 'is a NdrConfVarWideStringz' do
      expect(packet.shi1_remark).to be_a RubySMB::Dcerpc::Ndr::NdrConfVarWideStringz
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Srvsvc::SrvsvcHandle do
  it 'is a NdrWideStringzPtr' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrWideStringzPtr
  end
end
