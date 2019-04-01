RSpec.describe RubySMB::Dcerpc::Ndr::NdrTopLevelFullPointer do
  subject(:packet) do
    Class.new(described_class) do
      endian :little
      string :referent
    end.new
  end

  it { is_expected.to respond_to :referent_identifier }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#referent_identifier' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.referent_identifier).to be_a BinData::Uint32le
    end

    it 'has an initial value of 0x00020000' do
      expect(packet.referent_identifier).to eq(0x00020000)
    end
  end

  describe '#get' do
    it 'returns 0 when #referent_identifier is 0' do
      packet.referent_identifier = 0
      expect(packet.get).to eq(0)
    end

    it 'returns #referent when #referent_identifier is greater than 0' do
      packet.set('spec_test')
      expect(packet.get).to eq(packet.referent)
    end
  end

  describe '#set' do
    context 'when the value is 0' do
      it 'sets #referent_identifier to 0' do
        packet.set(0)
        expect(packet.referent_identifier).to eq(0)
      end
    end

    context 'when the value is a string' do
      it 'sets #referent to the value' do
        str = 'spec_test'
        packet.set(str)
        expect(packet.referent).to eq(str)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrString do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :max_count }
  it { is_expected.to respond_to :offset }
  it { is_expected.to respond_to :actual_count }
  it { is_expected.to respond_to :str }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#max_count' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.max_count).to be_a BinData::Uint32le
    end
  end

  describe '#offset' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.offset).to be_a BinData::Uint32le
    end

    it 'has an initial valu of 0' do
      expect(packet.offset).to eq(0)
    end
  end

  describe '#actual_count' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.actual_count).to be_a BinData::Uint32le
    end
  end

  describe '#str' do
    it 'is a RubySMB::Field::Stringz16' do
      expect(packet.str).to be_a RubySMB::Field::Stringz16
    end

    it 'exists if #actual_count is greater than 0' do
      packet.actual_count = 4
      expect(packet.str?).to be true
    end

    it 'does not exist if #actual_count is 0' do
      expect(packet.str?).to be false
    end
  end

  describe '#get' do
    it 'returns 0 when #actual_count is 0' do
      expect(packet.get).to eq(0)
    end

    it 'returns #str when #actual_count is greater than 0' do
      str = 'spec_test'
      strz16 = RubySMB::Field::Stringz16.new(str)
      packet.set(str)
      expect(packet.get).to eq(strz16)
    end
  end

  describe '#set' do
    context 'when the value is 0' do
      it 'sets #actual_count to 0' do
        packet.set(0)
        expect(packet.actual_count).to eq(0)
      end
    end

    context 'when the value is a string' do
      let(:str) { 'spec_test' }

      it 'sets #str to the value' do
        packet.set(str)
        strz16 = RubySMB::Field::Stringz16.new(str)
        expect(packet.str).to eq(strz16)
      end

      it 'sets #max_count and #actual_count to the expected value' do
        packet.set(str)
        expect(packet.max_count).to eq(str.length + 1)
        expect(packet.actual_count).to eq(str.length + 1)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrLpStr do
  it 'is NdrTopLevelFullPointer subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrTopLevelFullPointer
  end

  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :referent }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#referent' do
    it 'is a NdrString' do
      expect(packet.referent).to be_a RubySMB::Dcerpc::Ndr::NdrString
    end

    it 'exists if superclass #referent_identifier is not zero' do
      expect(packet.referent?).to be true
    end

    it 'does not exist if superclass #referent_identifier is zero' do
      packet.referent_identifier = 0
      expect(packet.referent?).to be false
    end
  end

  describe '#to_s' do
    it 'returns "\0" when #referent_identifier is 0' do
      packet.referent_identifier = 0
      expect(packet.to_s).to eq("\0")
    end

    it 'returns #referent when #referent_identifier is greater than 0' do
      packet.set('spec_test')
      expect(packet.to_s).to eq(packet.referent)
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrContextHandle do
  let(:uuid) { 'c3bce70d-5155-472b-9f2f-b824e5fc9b60' }
  let(:attr) { 123 }
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :context_handle_attributes }
  it { is_expected.to respond_to :context_handle_uuid }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#context_handle_attributes' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.context_handle_attributes).to be_a BinData::Uint32le
    end
  end

  describe '#context_handle_uuid' do
    it 'is a UUID' do
      expect(packet.context_handle_uuid).to be_a RubySMB::Dcerpc::Uuid
    end
  end

  describe '#get' do
    it 'returns the expeted hash' do
      packet.context_handle_attributes = attr
      packet.context_handle_uuid = uuid
      expect(packet.get).to eq({context_handle_attributes: attr, context_handle_uuid: uuid})
    end
  end

  describe '#set' do
    let(:handle) { {context_handle_attributes: attr, context_handle_uuid: uuid} }

    context 'when the value is a hash' do
      it 'sets #context_handle_attributes and #context_handle_uuid to the expected values' do
        packet.set(handle)
        expect(packet.context_handle_attributes).to eq(attr)
        expect(packet.context_handle_uuid).to eq(uuid)
      end
    end

    context 'when the value is a NdrContextHandle'do
      it 'reads the value binary representaion ' do
        ndr_context_handle = described_class.new(handle)
        allow(ndr_context_handle).to receive(:to_binary_s).and_call_original
        packet.set(ndr_context_handle)
        expect(ndr_context_handle).to have_received(:to_binary_s)
        expect(packet.get).to eq(ndr_context_handle)
      end
    end

    context 'when the value is a binary string'do
      it 'reads the value' do
        ndr_context_handle = described_class.new(handle)
        packet.set(ndr_context_handle.to_binary_s)
        expect(packet.get).to eq(ndr_context_handle)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrLpDword do
  it 'is NdrTopLevelFullPointer subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrTopLevelFullPointer
  end

  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :referent }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#referent' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.referent).to be_a BinData::Uint32le
    end

    it 'exists if superclass #referent_identifier is not zero' do
      expect(packet.referent?).to be true
    end

    it 'does not exist if superclass #referent_identifier is zero' do
      packet.referent_identifier = 0
      expect(packet.referent?).to be false
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrLpByte do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :referent_identifier }
  it { is_expected.to respond_to :max_count }
  it { is_expected.to respond_to :offset }
  it { is_expected.to respond_to :actual_count }
  it { is_expected.to respond_to :bytes }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#referent_identifier' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.referent_identifier).to be_a BinData::Uint32le
    end

    it 'has an initial value of 0x00020000' do
      expect(packet.referent_identifier).to eq(0x00020000)
    end
  end

  describe '#max_count' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.max_count).to be_a BinData::Uint32le
    end

    it 'has an initial value equal to #actual_count' do
      packet.actual_count = 345
      expect(packet.max_count).to eq(345)
    end

    it 'exists if #referent_identifier is not zero' do
      expect(packet.max_count?).to be true
    end

    it 'does not exist if #referent_identifier is zero' do
      packet.referent_identifier = 0
      expect(packet.max_count?).to be false
    end
  end

  describe '#offset' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.offset).to be_a BinData::Uint32le
    end

    it 'has an initial value of 0' do
      expect(packet.offset).to eq(0)
    end

    it 'exists if #referent_identifier is not zero' do
      expect(packet.offset?).to be true
    end

    it 'does not exist if #referent_identifier is zero' do
      packet.referent_identifier = 0
      expect(packet.offset?).to be false
    end
  end

  describe '#actual_count' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.actual_count).to be_a BinData::Uint32le
    end

    it 'has an initial value equal to #bytes size' do
      packet.bytes << 2 << 3 << 4 << 5
      expect(packet.actual_count).to eq(4)
    end

    it 'exists if #referent_identifier is not zero' do
      expect(packet.actual_count?).to be true
    end

    it 'does not exist if #referent_identifier is zero' do
      packet.referent_identifier = 0
      expect(packet.actual_count?).to be false
    end
  end

  describe '#bytes' do
    it 'is a Bindata::Array' do
      expect(packet.bytes).to be_a BinData::Array
    end

    it 'has an initial length equal to #actual_count' do
      packet.actual_count = 3
      expect(packet.bytes.size).to eq(3)
    end

    it 'is 8-bit unsigned integer elements' do
      expect(packet.bytes[0]).to be_a BinData::Uint8
    end

    it 'exists if #referent_identifier is not zero' do
      expect(packet.bytes?).to be true
    end

    it 'does not exist if #referent_identifier is zero' do
      packet.referent_identifier = 0
      expect(packet.bytes?).to be false
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrLpFileTime do
  it 'is NdrTopLevelFullPointer subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrTopLevelFullPointer
  end

  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :referent }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#referent' do
    it 'is a FileTime' do
      expect(packet.referent).to be_a RubySMB::Field::FileTime
    end

    it 'exists if superclass #referent_identifier is not zero' do
      expect(packet.referent?).to be true
    end

    it 'does not exist if superclass #referent_identifier is zero' do
      packet.referent_identifier = 0
      expect(packet.referent?).to be false
    end
  end
end
