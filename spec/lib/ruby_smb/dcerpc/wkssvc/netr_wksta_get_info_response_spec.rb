RSpec.describe RubySMB::Dcerpc::Wkssvc::WkstaInfo102 do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :wki102_platform_id }
  it { is_expected.to respond_to :wki102_computername }
  it { is_expected.to respond_to :wki102_langroup }
  it { is_expected.to respond_to :wki102_ver_major }
  it { is_expected.to respond_to :wki102_ver_minor }
  it { is_expected.to respond_to :wki102_lanroot }
  it { is_expected.to respond_to :wki102_logged_on_users }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'it is a Ndr::NdrStruct' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
  end
  describe '#wki102_platform_id' do
    it 'is a NdrUint32 structure' do
      expect(packet.wki102_platform_id).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#wki102_computername' do
    it 'is a Ndr::NdrWideStringzPtr' do
      expect(packet.wki102_computername).to be_a(RubySMB::Dcerpc::Ndr::NdrWideStringzPtr)
    end
  end
  describe '#wki102_langroup' do
    it 'is a Ndr::NdrWideStringzPtr' do
      expect(packet.wki102_langroup).to be_a(RubySMB::Dcerpc::Ndr::NdrWideStringzPtr)
    end
  end
  describe '#wki102_ver_major' do
    it 'is a NdrUint32 structure' do
      expect(packet.wki102_ver_major).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#wki102_ver_minor' do
    it 'is a NdrUint32 structure' do
      expect(packet.wki102_ver_minor).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#wki102_lanroot' do
    it 'is a Ndr::NdrWideStringzPtr' do
      expect(packet.wki102_lanroot).to be_a(RubySMB::Dcerpc::Ndr::NdrWideStringzPtr)
    end
  end
  describe '#wki102_logged_on_users' do
    it 'is a NdrUint32 structure' do
      expect(packet.wki102_logged_on_users).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  it 'reads itself' do
    new_class = described_class.new(
      wki102_platform_id: 500,
      wki102_computername: 'MYCOMPUTER',
      wki102_langroup: 'MYDOMAIN',
      wki102_ver_major: 6,
      wki102_ver_minor: 2,
      wki102_lanroot: 'MYLANROOT',
      wki102_logged_on_users: 4,
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        wki102_platform_id: 500,
        wki102_computername: 'MYCOMPUTER'.encode('utf-16le'),
        wki102_langroup: 'MYDOMAIN'.encode('utf-16le'),
        wki102_ver_major: 6,
        wki102_ver_minor: 2,
        wki102_lanroot: 'MYLANROOT'.encode('utf-16le'),
        wki102_logged_on_users: 4,
      }
    )
  end
end

RSpec.describe RubySMB::Dcerpc::Wkssvc::PwkstaInfo102 do
  subject(:packet) { described_class.new }

  it 'is a WkstaInfo102' do
    expect(packet).to be_a(RubySMB::Dcerpc::Wkssvc::WkstaInfo102)
  end
  it 'is a NDR Pointer' do
    expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
  end
  it 'reads itself' do
    new_class = described_class.new(
      wki102_platform_id: 500,
      wki102_computername: 'MYCOMPUTER',
      wki102_langroup: 'MYDOMAIN',
      wki102_ver_major: 6,
      wki102_ver_minor: 2,
      wki102_lanroot: 'MYLANROOT',
      wki102_logged_on_users: 4,
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        wki102_platform_id: 500,
        wki102_computername: 'MYCOMPUTER'.encode('utf-16le'),
        wki102_langroup: 'MYDOMAIN'.encode('utf-16le'),
        wki102_ver_major: 6,
        wki102_ver_minor: 2,
        wki102_lanroot: 'MYLANROOT'.encode('utf-16le'),
        wki102_logged_on_users: 4,
      }
    )
  end
end

RSpec.describe RubySMB::Dcerpc::Wkssvc::WkstaInfo101 do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :wki101_platform_id }
  it { is_expected.to respond_to :wki101_computername }
  it { is_expected.to respond_to :wki101_langroup }
  it { is_expected.to respond_to :wki101_ver_major }
  it { is_expected.to respond_to :wki101_ver_minor }
  it { is_expected.to respond_to :wki101_lanroot }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'it is a Ndr::NdrStruct' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
  end
  describe '#wki101_platform_id' do
    it 'is a NdrUint32 structure' do
      expect(packet.wki101_platform_id).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#wki101_computername' do
    it 'is a Ndr::NdrWideStringzPtr' do
      expect(packet.wki101_computername).to be_a(RubySMB::Dcerpc::Ndr::NdrWideStringzPtr)
    end
  end
  describe '#wki101_langroup' do
    it 'is a Ndr::NdrWideStringzPtr' do
      expect(packet.wki101_langroup).to be_a(RubySMB::Dcerpc::Ndr::NdrWideStringzPtr)
    end
  end
  describe '#wki101_ver_major' do
    it 'is a NdrUint32 structure' do
      expect(packet.wki101_ver_major).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#wki101_ver_minor' do
    it 'is a NdrUint32 structure' do
      expect(packet.wki101_ver_minor).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#wki101_lanroot' do
    it 'is a Ndr::NdrWideStringzPtr' do
      expect(packet.wki101_lanroot).to be_a(RubySMB::Dcerpc::Ndr::NdrWideStringzPtr)
    end
  end
  it 'reads itself' do
    new_class = described_class.new(
      wki101_platform_id: 500,
      wki101_computername: 'MYCOMPUTER',
      wki101_langroup: 'MYDOMAIN',
      wki101_ver_major: 6,
      wki101_ver_minor: 2,
      wki101_lanroot: 'MYLANROOT'
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        wki101_platform_id: 500,
        wki101_computername: 'MYCOMPUTER'.encode('utf-16le'),
        wki101_langroup: 'MYDOMAIN'.encode('utf-16le'),
        wki101_ver_major: 6,
        wki101_ver_minor: 2,
        wki101_lanroot: 'MYLANROOT'.encode('utf-16le')
      }
    )
  end
end

RSpec.describe RubySMB::Dcerpc::Wkssvc::PwkstaInfo101 do
  subject(:packet) { described_class.new }

  it 'is a WkstaInfo101' do
    expect(packet).to be_a(RubySMB::Dcerpc::Wkssvc::WkstaInfo101)
  end
  it 'is a NDR Pointer' do
    expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
  end
  it 'reads itself' do
    new_class = described_class.new(
      wki101_platform_id: 500,
      wki101_computername: 'MYCOMPUTER',
      wki101_langroup: 'MYDOMAIN',
      wki101_ver_major: 6,
      wki101_ver_minor: 2,
      wki101_lanroot: 'MYLANROOT'
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        wki101_platform_id: 500,
        wki101_computername: 'MYCOMPUTER'.encode('utf-16le'),
        wki101_langroup: 'MYDOMAIN'.encode('utf-16le'),
        wki101_ver_major: 6,
        wki101_ver_minor: 2,
        wki101_lanroot: 'MYLANROOT'.encode('utf-16le')
      }
    )
  end
end

RSpec.describe RubySMB::Dcerpc::Wkssvc::WkstaInfo100 do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :wki100_platform_id }
  it { is_expected.to respond_to :wki100_computername }
  it { is_expected.to respond_to :wki100_langroup }
  it { is_expected.to respond_to :wki100_ver_major }
  it { is_expected.to respond_to :wki100_ver_minor }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'it is a Ndr::NdrStruct' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
  end
  describe '#wki100_platform_id' do
    it 'is a NdrUint32 structure' do
      expect(packet.wki100_platform_id).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#wki100_computername' do
    it 'is a Ndr::NdrWideStringzPtr' do
      expect(packet.wki100_computername).to be_a(RubySMB::Dcerpc::Ndr::NdrWideStringzPtr)
    end
  end
  describe '#wki100_langroup' do
    it 'is a Ndr::NdrWideStringzPtr' do
      expect(packet.wki100_langroup).to be_a(RubySMB::Dcerpc::Ndr::NdrWideStringzPtr)
    end
  end
  describe '#wki100_ver_major' do
    it 'is a NdrUint32 structure' do
      expect(packet.wki100_ver_major).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#wki100_ver_minor' do
    it 'is a NdrUint32 structure' do
      expect(packet.wki100_ver_minor).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  it 'reads itself' do
    new_class = described_class.new(
      wki100_platform_id: 500,
      wki100_computername: 'MYCOMPUTER',
      wki100_langroup: 'MYDOMAIN',
      wki100_ver_major: 6,
      wki100_ver_minor: 2
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        wki100_platform_id: 500,
        wki100_computername: 'MYCOMPUTER'.encode('utf-16le'),
        wki100_langroup: 'MYDOMAIN'.encode('utf-16le'),
        wki100_ver_major: 6,
        wki100_ver_minor: 2
      }
    )
  end
end

RSpec.describe RubySMB::Dcerpc::Wkssvc::PwkstaInfo100 do
  subject(:packet) { described_class.new }

  it 'is a WkstaInfo100' do
    expect(packet).to be_a(RubySMB::Dcerpc::Wkssvc::WkstaInfo100)
  end
  it 'is a NDR Pointer' do
    expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
  end
  it 'reads itself' do
    new_class = described_class.new(
      wki100_platform_id: 500,
      wki100_computername: 'MYCOMPUTER',
      wki100_langroup: 'MYDOMAIN',
      wki100_ver_major: 6,
      wki100_ver_minor: 2
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        wki100_platform_id: 500,
        wki100_computername: 'MYCOMPUTER'.encode('utf-16le'),
        wki100_langroup: 'MYDOMAIN'.encode('utf-16le'),
        wki100_ver_major: 6,
        wki100_ver_minor: 2
      }
    )
  end
end

RSpec.describe RubySMB::Dcerpc::Wkssvc::LpwkstaInfo do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :level }
  it { is_expected.to respond_to :info }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'it is a Ndr::NdrStruct' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
  end
  describe '#level' do
    it 'is a NdrUint32 structure' do
      expect(packet.level).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#info' do
    it 'is a BinData:Choice structure' do
      expect(packet.info).to be_a BinData::Choice
    end
    it 'selects a structure according to :level value' do
      packet.level = RubySMB::Dcerpc::Wkssvc::WKSTA_INFO_100
      expect(packet.info.send(:current_choice)).to be_a(RubySMB::Dcerpc::Wkssvc::WkstaInfo100)
    end
  end
  it 'reads itself' do
    new_class = described_class.new(
      level: RubySMB::Dcerpc::Wkssvc::WKSTA_INFO_100,
      info: {
        wki100_platform_id: 500,
        wki100_computername: 'MYCOMPUTER',
        wki100_langroup: 'MYDOMAIN',
        wki100_ver_major: 6,
        wki100_ver_minor: 2
      }
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        level: RubySMB::Dcerpc::Wkssvc::WKSTA_INFO_100,
        info: {
          wki100_platform_id: 500,
          wki100_computername: 'MYCOMPUTER'.encode('utf-16le'),
          wki100_langroup: 'MYDOMAIN'.encode('utf-16le'),
          wki100_ver_major: 6,
          wki100_ver_minor: 2
        }
      }
    )
  end
end

RSpec.describe RubySMB::Dcerpc::Wkssvc::NetrWkstaGetInfoResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :wksta_info }
  it { is_expected.to respond_to :error_status }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#wksta_info' do
    it 'is a LpwkstaInfo structure' do
      expect(packet.wksta_info).to be_a RubySMB::Dcerpc::Wkssvc::LpwkstaInfo
    end
  end
  describe '#error_status' do
    it 'is a NdrUint32 structure' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to NETR_WKSTA_GET_INFO constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Wkssvc::NETR_WKSTA_GET_INFO)
    end
  end
  it 'reads itself' do
    new_class = described_class.new(
      wksta_info: {
        level: RubySMB::Dcerpc::Wkssvc::WKSTA_INFO_100,
        info: {
          wki100_platform_id: 500,
          wki100_computername: 'MYCOMPUTER',
          wki100_langroup: 'MYDOMAIN',
          wki100_ver_major: 6,
          wki100_ver_minor: 2
        }
      },
      error_status: 0
    )
    expect(packet.read(new_class.to_binary_s)).to eq(
      {
        wksta_info: {
          level: RubySMB::Dcerpc::Wkssvc::WKSTA_INFO_100,
          info: {
            wki100_platform_id: 500,
            wki100_computername: 'MYCOMPUTER'.encode('utf-16le'),
            wki100_langroup: 'MYDOMAIN'.encode('utf-16le'),
            wki100_ver_major: 6,
            wki100_ver_minor: 2
          }
        },
        error_status: 0
      }
    )
  end
end

