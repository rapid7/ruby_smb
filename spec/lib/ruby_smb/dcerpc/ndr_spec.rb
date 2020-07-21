RSpec.describe RubySMB::Dcerpc::Ndr::NdrPointer do
  subject(:packet) do
    Class.new(described_class) do
      endian :little
      string :referent
    end.new
  end

  it { is_expected.to respond_to :referent_id }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#referent_id' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.referent_id).to be_a BinData::Uint32le
    end

    it 'has an initial value of 0' do
      expect(packet.referent_id).to eq(0)
    end
  end

  describe '#get' do
    it 'returns :null when #referent_id is 0' do
      packet.referent_id = 0
      expect(packet.get).to eq(:null)
    end

    it 'returns #referent when #referent_id is not 0' do
      packet.set('spec_test')
      expect(packet.get).to eq(packet.referent)
    end
  end

  describe '#set' do
    context 'when the value is :null' do
      it 'clears #referent' do
        expect(packet.referent).to receive(:clear)
        packet.set(:null)
      end

      it 'sets #referent_id to 0' do
        packet.set(:null)
        expect(packet.referent_id).to eq(0)
      end
    end

    context 'when the value is a string' do
      let(:str) { 'spec_test' }

      it 'sets #referent to the value' do
        packet.set(str)
        expect(packet.referent).to eq(str)
      end

      it 'calls #set when #referent support it' do
        module TestSet; def set(v); end; end
        packet.referent.extend(TestSet)
        expect(packet.referent).to receive(:set).with(str)
        packet.set(str)
      end

      it 'assigns directly to #referent when it does not support #set' do
        expect(packet).to receive(:referent=).with(str)
        packet.set(str)
      end

      it 'sets #referent_id to a random value' do
        rnd = double('Random Value')
        allow(packet).to receive(:rand).and_return(rnd)
        expect(packet).to receive(:referent_id=).with(rnd)
        packet.set(str)
      end

      it 'does not change #referent_id if it is already set' do
        packet.referent_id = 0xCCCCCC
        packet.set(str)
        expect(packet.referent_id).to eq(0xCCCCCC)
      end
    end
  end

  describe '#do_read' do
    let(:io) { StringIO.new }

    it 'asks referent_id to read the io stream' do
      expect(packet.referent_id).to receive(:do_read).with(io)
      packet.do_read(io)
    end

    context 'when it can process #referent' do
      before :example do
        allow(packet).to receive(:process_referent?).and_return(true)
        allow(packet.referent_id).to receive(:do_read)
      end

      it 'asks referent to read the io stream if referent_id is not 0' do
        packet.referent_id = 0xCCCC
        expect(packet.referent).to receive(:do_read).with(io)
        packet.do_read(io)
      end

      it 'does not ask referent to read the io stream if referent_id is 0' do
        packet.referent_id = 0
        expect(packet.referent).to_not receive(:do_read).with(io)
        packet.do_read(io)
      end
    end
  end

  describe '#do_write' do
    let(:io) { StringIO.new }

    it 'asks referent_id to write the io stream' do
      expect(packet.referent_id).to receive(:do_write).with(io)
      packet.do_write(io)
    end

    context 'when it can process #referent' do
      before :example do
        allow(packet).to receive(:process_referent?).and_return(true)
        allow(packet.referent_id).to receive(:do_write)
      end

      it 'asks referent to write the io stream if referent_id is not 0' do
        packet.referent_id = 0xCCCC
        expect(packet.referent).to receive(:do_write).with(io)
        packet.do_write(io)
      end

      it 'does not ask referent to write the io stream if referent_id is 0' do
        packet.referent_id = 0
        expect(packet.referent).to_not receive(:do_write).with(io)
        packet.do_write(io)
      end
    end
  end

  describe '#process_referent?' do
    let(:ndr_struct) { RubySMB::Dcerpc::Ndr::NdrStruct.new }
    it 'returns false if the parent is a NdrStruct' do
      obj = described_class.new(nil, {}, ndr_struct)
      expect(obj.process_referent?).to be false
    end

    it 'returns false if one of the parents is a NdrStruct' do
      obj1 = described_class.new(nil, {}, ndr_struct)
      obj2 = described_class.new(nil, {}, obj1)
      obj3 = described_class.new(nil, {}, obj2)
      obj4 = described_class.new(nil, {}, obj3)
      obj5 = described_class.new(nil, {}, obj4)
      expect(obj5.process_referent?).to be false
    end

    it 'returns true if none of the parents is a NdrStruct' do
      obj1 = described_class.new
      obj2 = described_class.new(nil, {}, obj1)
      obj3 = described_class.new(nil, {}, obj2)
      obj4 = described_class.new(nil, {}, obj3)
      obj5 = described_class.new(nil, {}, obj4)
      expect(obj5.process_referent?).to be true
    end
  end

  describe '#read' do
    let(:struct) do
      Class.new(described_class) do
        attr_accessor :str_length
        endian :little
        string :referent, read_length: -> { self.str_length }
      end
    end

    context 'with a null string' do
      it 'reads its own binary representation' do
        raw = packet.to_binary_s
        expect(struct.read(raw)).to eq(packet)
        expect(struct.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with a normal string' do
      it 'reads its own binary representation' do
        packet.set('testing')
        raw = packet.to_binary_s
        struct_obj = struct.new
        struct_obj.str_length = 'testing'.size
        expect(struct_obj.read(raw)).to eq(packet)
        expect(struct_obj.read(raw).to_binary_s).to eq(raw)
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

      it 'clears #str' do
        expect(packet.str).to receive(:clear)
        packet.set(0)
      end

      it 'keeps #actual_count set to 0 when called from #to_binary_s' do
        packet.set(0)
        packet.to_binary_s
        expect(packet.actual_count).to eq(0)
      end

      it 'keeps #actual_count set to 0 when called from #do_num_bytes' do
        packet.set(0)
        packet.to_binary_s
        packet.do_num_bytes
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

      it 'sets #actual_count to 0 when the value is an empty string' do
        packet.actual_count = 10
        packet.set('')
        expect(packet.actual_count).to eq(0)
      end

      it 'keeps custom #max_count and #offset values when called from #to_binary_s' do
        packet.set(str)
        packet.max_count = 3
        packet.offset = 10
        packet.to_binary_s
        expect(packet.max_count).to eq(3)
        expect(packet.offset).to eq(10)
      end

      it 'keeps custom #max_count value when called from #do_num_bytes' do
        packet.set(str)
        packet.max_count = 3
        packet.offset = 10
        packet.do_num_bytes
        expect(packet.max_count).to eq(3)
        expect(packet.offset).to eq(10)
      end

      it 'sets #max_count to the number of elements set after setting custom #max_count value' do
        packet.set(str)
        packet.max_count = 3
        packet.set(str * 2)
        expect(packet.max_count).to eq(str.size * 2 + 1)
      end
    end
  end

  describe '#clear' do
    it 'clears #str' do
      expect(packet.str).to receive(:clear)
      packet.clear
    end

    it 'clears #actual_count' do
      expect(packet.actual_count).to receive(:clear)
      packet.clear
    end

    it 'does to clear out #max_count and #offset' do
      expect(packet.max_count).to_not receive(:clear)
      expect(packet.offset).to_not receive(:clear)
      packet.clear
    end
  end

  describe '#to_s' do
    it 'calls str#to_s' do
      expect(packet.str).to receive(:to_s)
      packet.to_s
    end

    it 'outputs the expected string with the correct encoding' do
      str = 'testing'
      packet.assign(str)
      expect(packet.to_s.encoding).to eq(Encoding::UTF_16LE)
      expect(packet.to_s).to eq(str.encode(Encoding::UTF_16LE))
    end
  end

  describe '#read' do
    context 'with a null string' do
      it 'reads its own binary representation' do
        packet.set(0)
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with a normal string' do
      it 'reads its own binary representation' do
        packet.set('testing')
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with different #offset and #max_count values' do
      it 'reads its own binary representation' do
        packet.set('testing')
        packet.max_count = 256
        packet.offset = 40
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with #actual_count less than elements size' do
      it 'reads its own binary representation reduced to #actual_count elements' do
        str = '12345'
        packet.set(str)
        packet.actual_count = 4
        max_count = packet.max_count.to_i
        raw = packet.to_binary_s
        packet2 = described_class.read(raw)
        expect(packet2.max_count).to eq(max_count)
        expect(packet2.offset).to eq(0)
        expect(packet2.actual_count).to eq(4)
        expect(packet2.str).to eq(str[0,3].encode(Encoding::UTF_16LE))
        expect(packet2.to_binary_s).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x001\x002\x003\x00\x00\x00".b)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrLpStr do
  it 'is NdrPointer subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrPointer
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

    it 'exists if superclass #referent_id is not zero' do
      packet.referent_id = 0xCCCC
      expect(packet.referent?).to be true
    end

    it 'does not exist if superclass #referent_id is zero' do
      packet.referent_id = 0
      expect(packet.referent?).to be false
    end
  end

  describe '#read' do
    context 'with a null pointer' do
      it 'reads its own binary representation' do
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with a normal string' do
      it 'reads its own binary representation' do
        packet.set('testing')
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
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

  describe '#read' do
    context 'with a hash' do
      it 'reads its own binary representation' do
        packet.set({context_handle_attributes: attr, context_handle_uuid: uuid})
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with a NdrContextHandle' do
      it 'reads its own binary representation' do
        nch = described_class.new
        nch.set({context_handle_attributes: attr, context_handle_uuid: uuid})
        packet.set(nch)
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with a binary string' do
      it 'reads its own binary representation' do
        packet.set("{\x00\x00\x00\r\xE7\xBC\xC3UQ+G\x9F/\xB8$\xE5\xFC\x9B`".b)
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrLpDword do
  it 'is NdrPointer subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrPointer
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

    it 'exists if superclass #referent_id is not zero' do
      packet.referent_id = 0xCCCC
      expect(packet.referent?).to be true
    end

    it 'does not exist if superclass #referent_id is zero' do
      packet.referent_id = 0
      expect(packet.referent?).to be false
    end
  end

  describe '#read' do
    context 'with a null pointer' do
      it 'reads its own binary representation' do
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with a normal integer' do
      it 'reads its own binary representation' do
        packet.set(123)
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrLpByteArray do
  it 'is NdrPointer subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrPointer
  end

  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :referent }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#referent' do
    it 'is a NdrByteArray structure' do
      expect(packet.referent).to be_a RubySMB::Dcerpc::Ndr::NdrByteArray
    end

    it 'exists if superclass #referent_id is not zero' do
      packet.referent_id = 0xCCCC
      expect(packet.referent?).to be true
    end

    it 'does not exist if superclass #referent_id is zero' do
      packet.referent_id = 0
      expect(packet.referent?).to be false
    end
  end

  describe '#set' do
    it 'accepts a NdrLpByteArray structure' do
      struct = described_class.new([1, 2, 3])
      packet.set(struct)
      expect(packet).to eq(struct)
    end

    it 'accepts a NdrLpByteArray null pointer' do
      struct = described_class.new
      packet.set(struct)
      expect(packet).to eq(:null)
    end

    it 'accepts a BinData::Array' do
      struct = BinData::Array.new([1, 2, 3], type: :uint8)
      packet.set(struct)
      expect(packet).to eq(struct)
    end

    it 'accepts an Array' do
      struct = Array.new([1, 2, 3])
      packet.set(struct)
      expect(packet).to eq(struct)
    end
  end

  describe '#read' do
    context 'with a null pointer' do
      it 'reads its own binary representation' do
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with a normal array of bytes' do
      it 'reads its own binary representation' do
        packet.set([1, 2, 3])
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrLpByte do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :max_count }
  it { is_expected.to respond_to :elements }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#max_count' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.max_count).to be_a BinData::Uint32le
    end

    it 'has an initial value equal to #elements size' do
      packet.elements = [1, 2, 3]
      expect(packet.max_count).to eq(3)
    end
  end

  describe '#elements' do
    it 'is a Bindata::Array' do
      expect(packet.elements).to be_a BinData::Array
    end

    it 'is 8-bit unsigned integer elements' do
      expect(packet.elements[0]).to be_a BinData::Uint8
    end

    it 'exists if #max_count is greater than 0' do
      packet.max_count = 2
      expect(packet.elements?).to be true
    end

    it 'does not exist if #max_count is 0' do
      packet.max_count = 0
      expect(packet.elements?).to be false
    end

    it 'reads at most #max_counts elements' do
      bin = "ABCDEFG".b
      packet.max_count = 3
      packet.elements.read(bin)
      expect(packet.elements).to eq(bin.bytes[0,3])
    end
  end

  describe '#get' do
    it 'returns the elements' do
      packet.elements = [1, 2, 3]
      expect(packet.get).to eq([1, 2, 3])
    end
  end

  describe '#set' do
    it 'sets #elements as expected' do
      packet.set([1, 2, 3])
      expect(packet.elements).to eq([1, 2, 3])
    end

    it 'sets #max_count to the number of elements set' do
      packet.set([1, 2, 3])
      expect(packet.max_count).to eq(3)
    end

    it 'calls #to_ary before setting the elements' do
      ary = BinData::Array.new([1, 2, 3], type: :uint8)
      expect(ary).to receive(:to_ary).and_call_original
      packet.set(ary)
      expect(packet.elements).to eq([1, 2, 3])
    end

    it 'keeps custom #max_count value when called from #to_binary_s' do
      packet.set([1, 2, 3, 4, 5])
      packet.max_count = 3
      packet.to_binary_s
      expect(packet.max_count).to eq(3)
    end

    it 'keeps custom #max_count value when called from #do_num_bytes' do
      packet.set([1, 2, 3, 4, 5])
      packet.max_count = 3
      packet.do_num_bytes
      expect(packet.max_count).to eq(3)
    end

    it 'sets #max_count to the number of elements set after setting custom #max_count value' do
      packet.set([1, 2, 3, 4, 5])
      packet.max_count = 3
      packet.set([1, 2, 3, 4, 5])
      expect(packet.max_count).to eq(5)
    end
  end

  describe '#read' do
    context 'with a no elements' do
      it 'reads its own binary representation' do
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with some elements' do
      it 'reads its own binary representation' do
        packet.set([1, 2, 3])
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with #max_count less than elements size' do
      it 'reads its own binary representation reduced to #max_count elements' do
        packet.set([1, 2, 3, 4, 5])
        packet.max_count = 3
        raw = packet.to_binary_s
        packet2 = described_class.new([1, 2, 3])
        raw2 = packet2.to_binary_s
        expect(described_class.read(raw)).to eq(packet2)
        expect(described_class.read(raw).to_binary_s).to eq(raw2)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrByteArray do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :max_count }
  it { is_expected.to respond_to :offset }
  it { is_expected.to respond_to :actual_count }
  it { is_expected.to respond_to :bytes }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#max_count' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.max_count).to be_a BinData::Uint32le
    end

    it 'has an initial value equal to #actual_count' do
      packet.actual_count = 345
      expect(packet.max_count).to eq(345)
    end
  end

  describe '#offset' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.offset).to be_a BinData::Uint32le
    end

    it 'has an initial value of 0' do
      expect(packet.offset).to eq(0)
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
  end

  describe '#get' do
    it 'returns bytes' do
      packet.bytes = [1, 2, 3]
      expect(packet.get).to eq([1, 2, 3])
    end
  end

  describe '#set' do
    it 'sets #bytes as expected' do
      packet.set([1, 2, 3])
      expect(packet.bytes).to eq([1, 2, 3])
    end

    it 'sets #actual_count and #max_count to the number of bytes set' do
      packet.set([1, 2, 3])
      expect(packet.max_count).to eq(3)
      expect(packet.actual_count).to eq(3)
    end

    it 'calls #to_ary before setting the elements' do
      ary = BinData::Array.new([1, 2, 3], type: :uint8)
      expect(ary).to receive(:to_ary).and_call_original
      packet.set(ary)
      expect(packet.bytes).to eq([1, 2, 3])
    end

    it 'keeps custom #max_count and #offset values when called from #to_binary_s' do
      packet.set([1, 2, 3, 4, 5])
      packet.max_count = 3
      packet.offset = 40
      packet.to_binary_s
      expect(packet.max_count).to eq(3)
      expect(packet.offset).to eq(40)
    end

    it 'keeps custom #max_count and #offset values when called from #do_num_bytes' do
      packet.set([1, 2, 3, 4, 5])
      packet.max_count = 3
      packet.offset = 40
      packet.do_num_bytes
      expect(packet.max_count).to eq(3)
      expect(packet.offset).to eq(40)
    end

    it 'sets #max_count to the number of bytes set after setting custom #max_count value' do
      packet.set([1, 2, 3, 4, 5])
      packet.max_count = 3
      packet.set([1, 2, 3, 4, 5])
      expect(packet.max_count).to eq(5)
    end
  end

  describe '#read' do
    context 'with a no elements' do
      it 'reads its own binary representation' do
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with some elements' do
      it 'reads its own binary representation' do
        packet.set([1, 2, 3])
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with #max_count less than elements size' do
      it 'reads its own binary representation reduced to #max_count elements' do
        packet.set([1, 2, 3, 4, 5])
        packet.actual_count = 3
        max_count = packet.max_count.to_i
        raw = packet.to_binary_s
        packet2 = described_class.read(raw)
        expect(packet2.max_count).to eq(max_count)
        expect(packet2.offset).to eq(0)
        expect(packet2.actual_count).to eq(3)
        expect(packet2.bytes).to eq([1, 2, 3])
        expect(packet2.to_binary_s).to eq("\x05\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x01\x02\x03".b)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrLpFileTime do
  it 'is NdrPointer subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrPointer
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

    it 'exists if superclass #referent_id is not zero' do
      packet.referent_id = 0xCCCC
      expect(packet.referent?).to be true
    end

    it 'does not exist if superclass #referent_id is zero' do
      packet.referent_id = 0
      expect(packet.referent?).to be false
    end
  end

  describe '#read' do
    context 'with a null pointer' do
      it 'reads its own binary representation' do
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with a normal FileTime' do
      it 'reads its own binary representation' do
        time = RubySMB::Field::FileTime.new(Time.now)
        packet.set(time)
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrStruct do
  describe '#do_read' do
    let(:io) { BinData::IO::Read.new(bin_str) }
    context 'with a structure containg an array of pointers to integer' do
      subject(:struct) do
        Class.new(described_class) do
          endian :little
          uint32 :a
          array  :b, type: :ndr_lp_dword, read_until: -> { index == a - 1 }
          uint32 :c
        end.new
      end

      context 'without null pointers' do
        let(:bin_str) do
          "\x03\x00\x00\x00" + # a
          "\xA8\xC9\x1D\x9D" + # b[0] referent_id
          "&_>=" +             # b[1] referent_id
          "T\r%\x18" +         # b[2] referent_id
          "7\x00\x00\x00" +    # c
          "\x01\x00\x00\x00" + # b[0]
          "\x02\x00\x00\x00" + # b[1]
          "\x03\x00\x00\x00"  # b[2]
        end

        it 'reads as expected' do
          struct.do_read(io)
          expect(struct.a).to eq(3)
          expect(struct.b).to eq([1, 2, 3])
          expect(struct.b[0].referent_id).to eq(2635975080)
          expect(struct.b[0].referent).to eq(1)
          expect(struct.b[1].referent_id).to eq(1027497766)
          expect(struct.b[1].referent).to eq(2)
          expect(struct.b[2].referent_id).to eq(405081428)
          expect(struct.b[2].referent).to eq(3)
          expect(struct.c).to eq(55)
        end
      end

      context 'with null pointers' do
        let(:bin_str) do
          "\x03\x00\x00\x00" + # a
          "\xA8\xC9\x1D\x9D" + # b[0] referent_id
          "\x00\x00\x00\x00" + # b[1] referent_id (null)
          "T\r%\x18" +         # b[2] referent_id
          "7\x00\x00\x00" +    # c
          "\x01\x00\x00\x00" + # b[0]
          "\x03\x00\x00\x00"  # b[2]
        end

        it 'reads as expected' do
          struct.do_read(io)
          expect(struct.a).to eq(3)
          expect(struct.b).to eq([1, :null, 3])
          expect(struct.b[0].referent_id).to eq(2635975080)
          expect(struct.b[0].referent).to eq(1)
          expect(struct.b[1].referent_id).to eq(0)
          expect(struct.b[2].referent_id).to eq(405081428)
          expect(struct.b[2].referent).to eq(3)
          expect(struct.c).to eq(55)
        end
      end
    end

    context 'with a structure containg an array of pointers to strings' do
      subject(:struct) do
        Class.new(described_class) do
          endian :little
          uint32 :a
          array  :b, type: :ndr_lp_str, read_until: -> { index == a - 1 }
          uint32 :c
        end.new
      end

      context 'without null pointers' do
        let(:bin_str) do
          "\x03\x00\x00\x00" + # a
          "\xA8\xC9\x1D\x9D" + # b[0] referent_id
          "&_>=" +             # b[1] referent_id
          "T\r%\x18" +         # b[2] referent_id
          "7\x00\x00\x00" +    # c
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x001\x00\x00\x00" + # b[0]
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x002\x00\x00\x00" + # b[1]
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00"   # b[2]
        end

        it 'reads as expected' do
          struct.do_read(io)
          str1 = 'test1'.encode(Encoding::UTF_16LE)
          str2 = 'test2'.encode(Encoding::UTF_16LE)
          str3 = 'test3'.encode(Encoding::UTF_16LE)
          expect(struct.a).to eq(3)
          expect(struct.b).to eq([str1, str2, str3])
          expect(struct.b[0].referent_id).to eq(2635975080)
          expect(struct.b[0].referent).to eq(str1)
          expect(struct.b[1].referent_id).to eq(1027497766)
          expect(struct.b[1].referent).to eq(str2)
          expect(struct.b[2].referent_id).to eq(405081428)
          expect(struct.b[2].referent).to eq(str3)
          expect(struct.c).to eq(55)
        end
      end

      context 'with null pointers' do
        let(:bin_str) do
          "\x03\x00\x00\x00" + # a
          "\xA8\xC9\x1D\x9D" + # b[0] referent_id
          "\x00\x00\x00\x00" + # b[1] referent_id (null)
          "T\r%\x18" +         # b[2] referent_id
          "7\x00\x00\x00" +    # c
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x001\x00\x00\x00" + # b[0]
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00"   # b[2]
        end

        it 'reads as expected' do
          struct.do_read(io)
          str1 = 'test1'.encode(Encoding::UTF_16LE)
          str3 = 'test3'.encode(Encoding::UTF_16LE)
          expect(struct.a).to eq(3)
          expect(struct.b).to eq([str1, :null, str3])
          expect(struct.b[0].referent_id).to eq(2635975080)
          expect(struct.b[0].referent).to eq(str1)
          expect(struct.b[1].referent_id).to eq(0)
          expect(struct.b[2].referent_id).to eq(405081428)
          expect(struct.b[2].referent).to eq(str3)
          expect(struct.c).to eq(55)
        end
      end

      context 'with null strings' do
        let(:bin_str) do
          "\x03\x00\x00\x00" + # a
          "\xA8\xC9\x1D\x9D" + # b[0] referent_id
          "&_>=" +             # b[1] referent_id
          "T\r%\x18" +         # b[2] referent_id
          "7\x00\x00\x00" +    # c
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x001\x00\x00\x00" + # b[0]
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + # b[1] null string
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00"   # b[2]
        end

        it 'reads as expected' do
          struct.do_read(io)
          str1 = 'test1'.encode(Encoding::UTF_16LE)
          str3 = 'test3'.encode(Encoding::UTF_16LE)
          expect(struct.a).to eq(3)
          expect(struct.b).to eq([str1, 0, str3])
          expect(struct.b[0].referent_id).to eq(2635975080)
          expect(struct.b[0].referent).to eq(str1)
          expect(struct.b[1].referent_id).to eq(1027497766)
          expect(struct.b[1].referent).to eq(0)
          expect(struct.b[2].referent_id).to eq(405081428)
          expect(struct.b[2].referent).to eq(str3)
          expect(struct.c).to eq(55)
        end
      end

      context 'with padding' do
        let(:bin_str) do
          "\x03\x00\x00\x00" + # a
          "\xA8\xC9\x1D\x9D" + # b[0] referent_id
          "&_>=" +             # b[1] referent_id
          "T\r%\x18" +         # b[2] referent_id
          "7\x00\x00\x00" +    # c
          "\x05\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00t\x00e\x00s\x00t\x00\x00\x00" + # b[0]
          "\x00\x00" + # pad
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x002\x00\x00\x00" + # b[1]
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00"   # b[2]
        end

        it 'reads as expected' do
          struct.do_read(io)
          str1 = 'test'.encode(Encoding::UTF_16LE)
          str2 = 'test2'.encode(Encoding::UTF_16LE)
          str3 = 'test3'.encode(Encoding::UTF_16LE)
          expect(struct.a).to eq(3)
          expect(struct.b).to eq([str1, str2, str3])
          expect(struct.b[0].referent_id).to eq(2635975080)
          expect(struct.b[0].referent).to eq(str1)
          expect(struct.b[1].referent_id).to eq(1027497766)
          expect(struct.b[1].referent).to eq(str2)
          expect(struct.b[2].referent_id).to eq(405081428)
          expect(struct.b[2].referent).to eq(str3)
          expect(struct.c).to eq(55)
        end
      end
    end

    context 'with a structure containg an pointers to strings' do
      subject(:struct) do
        Class.new(described_class) do
          endian :little
          uint32     :a
          ndr_lp_str :b
          ndr_lp_str :c
          ndr_lp_str :d
          uint32     :e
        end.new
      end

      context 'without null pointers' do
        let(:bin_str) do
          "\x03\x00\x00\x00" + # a
          "\xA8\xC9\x1D\x9D" + # b referent_id
          "&_>=" +             # c referent_id
          "T\r%\x18" +         # d referent_id
          "7\x00\x00\x00" +    # c
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x001\x00\x00\x00" + # b
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x002\x00\x00\x00" + # c
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00"   # d
        end

        it 'reads as expected' do
          struct.do_read(io)
          str1 = 'test1'.encode(Encoding::UTF_16LE)
          str2 = 'test2'.encode(Encoding::UTF_16LE)
          str3 = 'test3'.encode(Encoding::UTF_16LE)
          expect(struct.a).to eq(3)
          expect(struct.b).to eq(str1)
          expect(struct.c).to eq(str2)
          expect(struct.d).to eq(str3)
          expect(struct.b.referent_id).to eq(2635975080)
          expect(struct.b.referent).to eq(str1)
          expect(struct.c.referent_id).to eq(1027497766)
          expect(struct.c.referent).to eq(str2)
          expect(struct.d.referent_id).to eq(405081428)
          expect(struct.d.referent).to eq(str3)
          expect(struct.e).to eq(55)
        end
      end

      context 'with null pointers' do
        let(:bin_str) do
          "\x03\x00\x00\x00" + # a
          "\xA8\xC9\x1D\x9D" + # b referent_id
          "\x00\x00\x00\x00" + # c referent_id (null)
          "T\r%\x18" +         # d referent_id
          "7\x00\x00\x00" +    # c
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x001\x00\x00\x00" + # b
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00"   # d
        end

        it 'reads as expected' do
          struct.do_read(io)
          str1 = 'test1'.encode(Encoding::UTF_16LE)
          str3 = 'test3'.encode(Encoding::UTF_16LE)
          expect(struct.a).to eq(3)
          expect(struct.b).to eq(str1)
          expect(struct.c).to eq(:null)
          expect(struct.d).to eq(str3)
          expect(struct.b.referent_id).to eq(2635975080)
          expect(struct.b.referent).to eq(str1)
          expect(struct.c.referent_id).to eq(0)
          expect(struct.d.referent_id).to eq(405081428)
          expect(struct.d.referent).to eq(str3)
          expect(struct.e).to eq(55)
        end
      end

      context 'with null strings' do
        let(:bin_str) do
          "\x03\x00\x00\x00" + # a
          "\xA8\xC9\x1D\x9D" + # b referent_id
          "&_>=" +             # c referent_id
          "T\r%\x18" +         # d referent_id
          "7\x00\x00\x00" +    # c
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x001\x00\x00\x00" + # b
          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + # c null string
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00"   # d
        end

        it 'reads as expected' do
          struct.do_read(io)
          str1 = 'test1'.encode(Encoding::UTF_16LE)
          str3 = 'test3'.encode(Encoding::UTF_16LE)
          expect(struct.a).to eq(3)
          expect(struct.b).to eq(str1)
          expect(struct.c).to eq(0)
          expect(struct.d).to eq(str3)
          expect(struct.b.referent_id).to eq(2635975080)
          expect(struct.b.referent).to eq(str1)
          expect(struct.c.referent_id).to eq(1027497766)
          expect(struct.c.referent).to eq(0)
          expect(struct.d.referent_id).to eq(405081428)
          expect(struct.d.referent).to eq(str3)
          expect(struct.e).to eq(55)
        end
      end

      context 'with padding' do
        let(:bin_str) do
          "\x03\x00\x00\x00" + # a
          "\xA8\xC9\x1D\x9D" + # b referent_id
          "&_>=" +             # c referent_id
          "T\r%\x18" +         # d referent_id
          "7\x00\x00\x00" +    # c
          "\x05\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00t\x00e\x00s\x00t\x00\x00\x00" + # b
          "\x00\x00" + # pad
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x002\x00\x00\x00" + # c
          "\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00"   # d
        end

        it 'reads as expected' do
          struct.do_read(io)
          str1 = 'test'.encode(Encoding::UTF_16LE)
          str2 = 'test2'.encode(Encoding::UTF_16LE)
          str3 = 'test3'.encode(Encoding::UTF_16LE)
          expect(struct.a).to eq(3)
          expect(struct.b).to eq(str1)
          expect(struct.c).to eq(str2)
          expect(struct.d).to eq(str3)
          expect(struct.b.referent_id).to eq(2635975080)
          expect(struct.b.referent).to eq(str1)
          expect(struct.c.referent_id).to eq(1027497766)
          expect(struct.c.referent).to eq(str2)
          expect(struct.d.referent_id).to eq(405081428)
          expect(struct.d.referent).to eq(str3)
          expect(struct.e).to eq(55)
        end
      end
    end
  end

  describe '#do_write' do
    let(:raw_io) { BinData::IO.create_string_io }
    let(:io) { BinData::IO::Write.new(raw_io) }
    context 'with a structure containg an array of pointers to integer' do
      subject(:struct) do
        Class.new(described_class) do
          endian :little
          uint32 :a
          array  :b, type: :ndr_lp_dword, read_until: -> { index == a - 1 }
          uint32 :c
        end.new
      end

      context 'without null pointers' do
        let(:packet) do
          struct.new(a: 3, b: [1, 2, 3], c: 55)
        end

        it 'writes as expected' do
          packet.do_write(io)
          raw_io.rewind
          expect(raw_io.read(4)).to eq("\x03\x00\x00\x00".b) # a
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[0] referent_id (random but not null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[1] referent_id (random but not null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[2] referent_id (random but not null)
          expect(raw_io.read(4)).to eq("7\x00\x00\x00".b) # c
          expect(raw_io.read(4)).to eq("\x01\x00\x00\x00".b) # b[0]
          expect(raw_io.read(4)).to eq("\x02\x00\x00\x00".b) # b[1]
          expect(raw_io.read(4)).to eq("\x03\x00\x00\x00".b) # b[2]
          expect(raw_io.eof).to be true
        end
      end

      context 'with null pointers' do
        let(:packet) do
          struct.new(a: 3, b: [1, :null, 3], c: 55)
        end

        it 'writes as expected' do
          packet.do_write(io)
          raw_io.rewind
          expect(raw_io.read(4)).to eq("\x03\x00\x00\x00".b) # a
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[0] referent_id (random but not null)
          expect(raw_io.read(4)).to eq("\x00\x00\x00\x00".b) # b[1] referent_id (null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[2] referent_id (random but not null)
          expect(raw_io.read(4)).to eq("7\x00\x00\x00".b) # c
          expect(raw_io.read(4)).to eq("\x01\x00\x00\x00".b) # b[0]
          expect(raw_io.read(4)).to eq("\x03\x00\x00\x00".b) # b[2]
          expect(raw_io.eof).to be true
        end
      end
    end

    context 'with a structure containg an array of pointers to strings' do
      subject(:struct) do
        Class.new(described_class) do
          endian :little
          uint32 :a
          array  :b, type: :ndr_lp_str, read_until: -> { index == a - 1 }
          uint32 :c
        end.new
      end

      context 'without null pointers' do
        let(:packet) do
          struct.new(a: 3, b: ['test1', 'test2', 'test3'], c: 55)
        end

        it 'writes as expected' do
          packet.do_write(io)
          raw_io.rewind
          expect(raw_io.read(4)).to eq("\x03\x00\x00\x00".b) # a
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[0] referent_id (random but not null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[1] referent_id (random but not null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[2] referent_id (random but not null)
          expect(raw_io.read(4)).to eq("7\x00\x00\x00".b) # c
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x001\x00\x00\x00".b) # b[0]
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x002\x00\x00\x00".b) # b[1]
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00".b) # b[2]
          expect(raw_io.eof).to be true
        end
      end

      context 'with null pointers' do
        let(:packet) do
          struct.new(a: 3, b: ['test1', :null, 'test3'], c: 55)
        end

        it 'writes as expected' do
          packet.do_write(io)
          raw_io.rewind
          expect(raw_io.read(4)).to eq("\x03\x00\x00\x00".b) # a
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[0] referent_id (random but not null)
          expect(raw_io.read(4)).to eq("\x00\x00\x00\x00".b) # b[1] referent_id (null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[2] referent_id (random but not null)
          expect(raw_io.read(4)).to eq("7\x00\x00\x00".b) # c
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x001\x00\x00\x00".b) # b[0]
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00".b) # b[2]
          expect(raw_io.eof).to be true
        end
      end

      context 'with null strings' do
        let(:packet) do
          struct.new(a: 3, b: ['test1', 0, 'test3'], c: 55)
        end

        it 'writes as expected' do
          packet.do_write(io)
          raw_io.rewind
          expect(raw_io.read(4)).to eq("\x03\x00\x00\x00".b) # a
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[0] referent_id (random but not null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[1] referent_id (random but not null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[2] referent_id (random but not null)
          expect(raw_io.read(4)).to eq("7\x00\x00\x00".b) # c
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x001\x00\x00\x00".b) # b[0]
          expect(raw_io.read(12)).to eq("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".b) # b[1] null string
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00".b) # b[2]
          expect(raw_io.eof).to be true
        end
      end

      context 'with padding' do
        let(:packet) do
          struct.new(a: 3, b: ['test1', 'test', 'test3'], c: 55)
        end

        it 'writes as expected' do
          packet.do_write(io)
          raw_io.rewind
          expect(raw_io.read(4)).to eq("\x03\x00\x00\x00".b) # a
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[0] referent_id (random but not null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[1] referent_id (random but not null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b[2] referent_id (random but not null)
          expect(raw_io.read(4)).to eq("7\x00\x00\x00".b) # c
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x001\x00\x00\x00".b) # b[0]
          expect(raw_io.read(22)).to eq("\x05\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00t\x00e\x00s\x00t\x00\x00\x00".b) # b[1]
          expect(raw_io.read(2)).to eq("\x00\x00".b) # pad
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00".b) # b[2]
          expect(raw_io.eof).to be true
        end
      end
    end

    context 'with a structure containg pointers to strings' do
      subject(:struct) do
        Class.new(described_class) do
          endian :little
          uint32     :a
          ndr_lp_str :b
          ndr_lp_str :c
          ndr_lp_str :d
          uint32     :e
        end.new
      end

      context 'without null pointers' do
        let(:packet) do
          struct.new(a: 3, b: 'test1', c: 'test2', d: 'test3', e: 55)
        end

        it 'writes as expected' do
          packet.do_write(io)
          raw_io.rewind
          expect(raw_io.read(4)).to eq("\x03\x00\x00\x00".b) # a
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b referent_id (random but not null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # c referent_id (random but not null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # d referent_id (random but not null)
          expect(raw_io.read(4)).to eq("7\x00\x00\x00".b) # e
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x001\x00\x00\x00".b) # b
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x002\x00\x00\x00".b) # c
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00".b) # d
          expect(raw_io.eof).to be true
        end
      end

      context 'with null pointers' do
        let(:packet) do
          struct.new(a: 3, b: 'test1', c: :null, d: 'test3', e: 55)
        end

        it 'writes as expected' do
          packet.do_write(io)
          raw_io.rewind
          expect(raw_io.read(4)).to eq("\x03\x00\x00\x00".b) # a
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b referent_id (random but not null)
          expect(raw_io.read(4)).to eq("\x00\x00\x00\x00".b) # c referent_id (null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # d referent_id (random but not null)
          expect(raw_io.read(4)).to eq("7\x00\x00\x00".b) # e
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x001\x00\x00\x00".b) # b
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00".b) # d
          expect(raw_io.eof).to be true
        end
      end

      context 'with null strings' do
        let(:packet) do
          struct.new(a: 3, b: 'test1', c: 0, d: 'test3', e: 55)
        end

        it 'writes as expected' do
          packet.do_write(io)
          raw_io.rewind
          expect(raw_io.read(4)).to eq("\x03\x00\x00\x00".b) # a
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b referent_id (random but not null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # c referent_id (random but not null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # d referent_id (random but not null)
          expect(raw_io.read(4)).to eq("7\x00\x00\x00".b) # e
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x001\x00\x00\x00".b) # b
          expect(raw_io.read(12)).to eq("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".b) # c
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00".b) # d
          expect(raw_io.eof).to be true
        end
      end

      context 'with padding' do
        let(:packet) do
          struct.new(a: 3, b: 'test1', c: 'test', d: 'test3', e: 55)
        end

        it 'writes as expected' do
          packet.do_write(io)
          raw_io.rewind
          expect(raw_io.read(4)).to eq("\x03\x00\x00\x00".b) # a
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # b referent_id (random but not null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # c referent_id (random but not null)
          expect(raw_io.read(4)).to_not eq("\x00\x00\x00\x00".b) # d referent_id (random but not null)
          expect(raw_io.read(4)).to eq("7\x00\x00\x00".b) # e
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x001\x00\x00\x00".b) # b
          expect(raw_io.read(22)).to eq("\x05\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00t\x00e\x00s\x00t\x00\x00\x00".b) # c
          expect(raw_io.read(2)).to eq("\x00\x00".b) # pad
          expect(raw_io.read(24)).to eq("\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00t\x00e\x00s\x00t\x003\x00\x00\x00".b) # d
          expect(raw_io.eof).to be true
        end
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrStringPtrsw do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :max_count }
  it { is_expected.to respond_to :elements }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#max_count' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.max_count).to be_a BinData::Uint32le
    end

    it 'has an initial value equal to #elements size' do
      packet.elements = ['A', 'B', 'C']
      expect(packet.max_count).to eq(3)
    end
  end

  describe '#elements' do
    it 'is a Bindata::Array' do
      expect(packet.elements).to be_a BinData::Array
    end

    it 'is an array of NdrLpStr' do
      expect(packet.elements[0]).to be_a RubySMB::Dcerpc::Ndr::NdrLpStr
    end

    it 'exists if #max_count is greater than 0' do
      packet.max_count = 2
      expect(packet.elements?).to be true
    end

    it 'does not exist if #max_count is 0' do
      packet.max_count = 0
      expect(packet.elements?).to be false
    end
  end

  describe '#get' do
    it 'returns elements' do
      packet.elements = ['1', '2', '3']
      expect(packet.get).to eq(['1', '2', '3'].map {|e| e.encode(Encoding::UTF_16LE)})
    end
  end

  describe '#set' do
    it 'sets #elements as expected' do
      packet.set(['1', '2', '3'])
      expect(packet.elements).to eq(['1', '2', '3'].map {|e| e.encode(Encoding::UTF_16LE)})
    end

    it 'sets #max_count to the number of elements set' do
      packet.set(['1', '2', '3'])
      expect(packet.max_count).to eq(3)
    end

    it 'calls #to_ary before setting the elements' do
      ary = BinData::Array.new(['1','2', '3'], type: :ndr_lp_str)
      expect(ary).to receive(:to_ary).and_call_original
      packet.set(ary)
      expect(packet.elements).to eq(['1', '2', '3'].map {|e| e.encode(Encoding::UTF_16LE)})
    end

    it 'keeps custom #max_count value when called from #to_binary_s' do
      packet.set(['1', '2', '3', '4', '5'])
      packet.max_count = 3
      packet.to_binary_s
      expect(packet.max_count).to eq(3)
    end

    it 'keeps custom #max_count and #offset values when called from #do_num_bytes' do
      packet.set(['1', '2', '3', '4', '5'])
      packet.max_count = 3
      packet.do_num_bytes
      expect(packet.max_count).to eq(3)
    end

    it 'sets #max_count to the number of elements set after setting custom #max_count value' do
      packet.set(['1', '2', '3', '4', '5'])
      packet.max_count = 3
      packet.set(['1', '2', '3', '4', '5'])
      expect(packet.max_count).to eq(5)
    end
  end

  describe '#read' do
    context 'with a no elements' do
      it 'reads its own binary representation' do
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with some elements' do
      it 'reads its own binary representation' do
        packet.set(['1', '2', '3'])
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrLpStringPtrsw do
  it 'is NdrPointer subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrPointer
  end

  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :referent }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#referent' do
    it 'is a NdrStringPtrsw structure' do
      expect(packet.referent).to be_a RubySMB::Dcerpc::Ndr::NdrStringPtrsw
    end

    it 'exists if superclass #referent_id is not zero' do
      packet.referent_id = 0xCCCC
      expect(packet.referent?).to be true
    end

    it 'does not exist if superclass #referent_id is zero' do
      packet.referent_id = 0
      expect(packet.referent?).to be false
    end
  end

  describe '#set' do
    it 'calls #to_ary before setting the elements, if supported' do
      ary = BinData::Array.new(['1', '2', '3'], type: :ndr_lp_str)
      expect(ary).to receive(:to_ary).and_call_original
      packet.set(ary)
      expect(packet.elements).to eq(['1', '2', '3'].map {|e| e.encode(Encoding::UTF_16LE)})
    end
  end

  describe '#read' do
    context 'with a null pointer' do
      it 'reads its own binary representation' do
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end

    context 'with a normal NdrStringPtrsw structure' do
      it 'reads its own binary representation' do
        packet.set(['1', '2', '3'])
        raw = packet.to_binary_s
        expect(described_class.read(raw)).to eq(packet)
        expect(described_class.read(raw).to_binary_s).to eq(raw)
      end
    end
  end
end
