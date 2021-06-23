require 'ruby_smb/dcerpc/ndr'

RSpec.describe RubySMB::Dcerpc::Ndr::Boolean do
  it 'is a BinData::Uint32le class' do
    expect(described_class).to be < BinData::Uint32le
  end
  it 'has :byte_align parameter set to the expected value' do
    expect(described_class.default_parameters[:byte_align]).to eq(4)
  end

  subject(:boolean) { described_class.new }

  context 'with #new' do
    it 'is false its default value' do
      expect(boolean.new).to eq(false)
    end
    it 'sets true to true' do
      expect(boolean.new(true)).to eq(true)
    end
    it 'sets false to false' do
      expect(boolean.new(false)).to eq(false)
    end
    it 'sets 1 to true' do
      expect(boolean.new(1)).to eq(true)
    end
    it 'sets 0 to false' do
      expect(boolean.new(0)).to eq(false)
    end
    it 'sets any integer > 0 to true' do
      expect(boolean.new(rand(1..1000))).to eq(true)
    end
    it 'raises an ArgumentError error when passing a String' do
      expect { boolean.new("false") }.to raise_error(ArgumentError)
    end
  end

  context 'with #assign' do
    it 'sets true to true' do
      boolean.assign(true)
      expect(boolean).to eq(true)
    end
    it 'sets false to false' do
      boolean.assign(false)
      expect(boolean).to eq(false)
    end
    it 'sets 1 to true' do
      boolean.assign(1)
      expect(boolean).to eq(true)
    end
    it 'sets 0 to false' do
      boolean.assign(0)
      expect(boolean).to eq(false)
    end
    it 'sets any integer > 0 to true' do
      boolean.assign(rand(1..100))
      expect(boolean).to eq(true)
    end
    it 'raises an ArgumentError error when passing a String' do
      expect { boolean.assign("false") }.to raise_error(ArgumentError)
    end
  end

  context 'when reading data' do
    it 'sets false with an uint32 zero value' do
      boolean.read("\x00\x00\x00\x00")
      expect(boolean).to eq(false)
    end
    it 'sets true with an uint32 1 value' do
      boolean.read("\x01\x00\x00\x00")
      expect(boolean).to eq(true)
    end
    it 'sets true with any uint32 value > 0' do
      boolean.read([rand(1..1000)].pack('L'))
      expect(boolean).to eq(true)
    end
    it 'reads itself' do
      expect(boolean.read(described_class.new(true).to_binary_s)).to eq(true)
    end
  end

  context 'with #to_binary_s' do
    it 'returns the expected true binary representation' do
      boolean.assign(true)
      expect(boolean.to_binary_s).to eq("\x01\x00\x00\x00")
    end
    it 'returns the expected false binary representation' do
      boolean.assign(false)
      expect(boolean.to_binary_s).to eq("\x00\x00\x00\x00")
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::Char do
  it 'is a BinData::String class' do
    expect(described_class).to be < BinData::String
  end
  it 'has :byte_align parameter set to the expected value' do
    expect(described_class.default_parameters[:byte_align]).to eq(1)
  end

  subject(:char) { described_class.new }

  context 'with #new' do
    it 'is "\x00" its default value' do
      expect(char.new).to eq("\x00")
    end
    it 'sets a character' do
      expect(char.new('A')).to eq('A')
    end
    it 'sets the first character when passing a String' do
      expect(char.new('ABC')).to eq('A')
    end
    it 'does not set a value when passing anything else than a string' do
      char.new(['ABC'])
      expect(char).to eq("\x00")
      char.new(67)
      expect(char).to eq("\x00")
    end
  end

  context 'with #assign' do
    it 'sets a character' do
      char.assign('A')
      expect(char).to eq('A')
    end
    it 'sets the first character when passing a String' do
      char.assign('ABC')
      expect(char).to eq('A')
    end
    it 'converts the argument to string and keeps the first character' do
      char.assign(['ABC'])
      expect(char).to eq('[')
      char.assign(67)
      expect(char).to eq('6')
    end
  end

  context 'when reading data' do
    it 'sets a character' do
      char.read("\x41")
      expect(char).to eq('A')
    end
    it 'reads itself' do
      expect(char.read(described_class.new('A').to_binary_s)).to eq('A')
    end
  end

  context 'with #to_binary_s' do
    it 'returns the expected character binary representation' do
      char.assign('A')
      expect(char.to_binary_s).to eq("\x41")
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::WideChar do
  it 'is a RubySMB::Field::String16 class' do
    expect(described_class).to be < RubySMB::Field::String16
  end
  it 'has :byte_align parameter set to the expected value' do
    expect(described_class.default_parameters[:byte_align]).to eq(2)
  end

  subject(:char) { described_class.new }

  context 'with #new' do
    it 'is "\x00" its default value' do
      expect(char.new).to eq("\x00".encode('utf-16le'))
    end
    it 'sets a character' do
      expect(char.new('A')).to eq('A'.encode('utf-16le'))
    end
    it 'sets the first character when passing a String' do
      expect(char.new('ABC')).to eq('A'.encode('utf-16le'))
    end
    it 'does not set a value when passing anything else than a string' do
      char.new(['ABC'])
      expect(char).to eq("\x00".encode('utf-16le'))
      char.new(67)
      expect(char).to eq("\x00".encode('utf-16le'))
    end
  end

  context 'with #assign' do
    it 'sets a character' do
      char.assign('A')
      expect(char).to eq('A'.encode('utf-16le'))
    end
    it 'sets the first character when passing a String' do
      char.assign('ABC')
      expect(char).to eq('A'.encode('utf-16le'))
    end
    it 'converts the argument to string and keeps the first character' do
      char.assign(['ABC'])
      expect(char).to eq('['.encode('utf-16le'))
      char.assign(67)
      expect(char).to eq('6'.encode('utf-16le'))
    end
  end

  context 'when reading data' do
    it 'sets a character' do
      char.read("\x41\x00")
      expect(char).to eq('A'.encode('utf-16le'))
    end
    it 'reads itself' do
      expect(char.read(described_class.new('A').to_binary_s)).to eq('A'.encode('utf-16le'))
    end
  end

  context 'with #to_binary_s' do
    it 'returns the expected character binary representation' do
      char.assign('A')
      expect(char.to_binary_s).to eq("\x41\x00")
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::Enum do
  it 'is a BinData::Int16le class' do
    expect(described_class).to be < BinData::Int16le
  end
  it 'has :byte_align parameter set to the expected value' do
    expect(described_class.default_parameters[:byte_align]).to eq(2)
  end
end

{
  NdrUint8: { parent_class: :Uint8, nb_bytes: 1},
  NdrUint16: { parent_class: :Uint16le, nb_bytes: 2},
  NdrUint32: { parent_class: :Uint32le, nb_bytes: 4},
  NdrUint64: { parent_class: :Uint64le, nb_bytes: 8},
}.each do |klass, info|
  RSpec.describe(RubySMB::Dcerpc::Ndr.const_get(klass)) do
    it "is a BinData::#{info[:parent_class]} class" do
      expect(described_class).to be < BinData.const_get(info[:parent_class])
    end
    it 'has :byte_align parameter set to the expected value' do
      expect(described_class.default_parameters[:byte_align]).to eq(info[:nb_bytes])
    end
  end
end

#####################################
#       NDR Constructed Types       #
#####################################


#
# Arrays
#

RSpec.shared_examples "a BinData::Array" do
  it 'is a BinData::Array class' do
    expect(described_class).to be < BinData::Array
  end
  it 'is an empty array by default' do
    expect(subject).to eq([])
  end

  context 'with elements' do
    before :example do
      subject << 5
      subject << 7
    end
    it 'contains the expected element types' do
      expect(subject.all? {|e| e.is_a?(RubySMB::Dcerpc::Ndr::NdrUint16)}).to be true
    end
    it 'has the expected size' do
      expect(subject.size).to eq(2)
    end

    context 'when setting a value at index greater than the current number of elements' do
      before :example do
        subject[4] = 14
      end
      it 'adds elements until it reaches the new index' do
        expect(subject.size).to eq(5)
      end
      it 'sets the new elements to the element type default value' do
        expect(subject[0]).to eq(5)
        expect(subject[1]).to eq(7)
        expect(subject[2]).to eq(0)
        expect(subject[3]).to eq(0)
        expect(subject[4]).to eq(14)
      end
    end

    context 'when reading a value at index greater than the current number of elements' do
      let(:new_element) {BinData::Uint16le.new(1)}
      before :example do
        new_element.assign(subject[4])
      end
      it 'adds elements until it reaches the new index' do
        expect(subject.size).to eq(5)
      end
      it 'adds elements a default element' do
        expect(new_element).to eq(0)
      end
      it 'sets the new elements to the element type default value' do
        expect(subject[0]).to eq(5)
        expect(subject[1]).to eq(7)
        expect(subject[2]).to eq(0)
        expect(subject[3]).to eq(0)
        expect(subject[4]).to eq(new_element)
      end
    end

    context 'when assigning another array' do
      let(:new_array) { [1,2,3] }
      before :example do
        subject.assign(new_array)
      end
      it 'has the same size than the other array' do
        expect(subject.size).to eq(new_array.size)
      end
      it 'replaces all the elements' do
        new_array.each_with_index do |e, i|
          expect(subject[i]).to eq(e)
        end
      end
    end
  end
end

RSpec.shared_examples "a NDR Array" do |counter|
  counter.each do |name, position|
    it "has #{name} set to 0 (uint32) by default" do
      expect(subject.to_binary_s[position*4, 4]).to eq("\x00\x00\x00\x00")
    end
  end
  it 'reads itself' do
    subject << 5
    subject << 7
    subject << 45
    expect(subject.read(subject.to_binary_s)).to eq([5, 7, 45])
  end
  it 'has :byte_align parameter set to the expected value' do
    expect(subject.eval_parameter(:byte_align)).to eq(4)
  end

  context 'when checking if its elements have :byte_align parameter set' do
    it 'does not raise error when the :byte_align parameter is set in the element class' do
      test_element = Class.new(BinData::Record) do
        default_parameters byte_align: 4
        endian :little
        uint32 :a
      end
      BinData::RegisteredClasses.register('test_element', test_element)
      expect { described_class.new(type: :test_element, byte_align: 4) }.to_not raise_error
    end
    it 'does not raise error when the :byte_align parameter is set during instantiation' do
      test_element = Class.new(BinData::Record) do
        endian :little
        uint32 :a
      end
      BinData::RegisteredClasses.register('test_element', test_element)
      expect { described_class.new(type: [:test_element, {byte_align: 4}], byte_align: 4) }.to_not raise_error
    end
    context 'with a NDR element' do
      it 'does not raise error when the type element is a symbol' do
        expect { described_class.new(type: :ndr_uint32, byte_align: 4) }.to_not raise_error
      end
      it 'does not raise error when the type element is a class' do
        expect { described_class.new(type: RubySMB::Dcerpc::Ndr::NdrUint32, byte_align: 4) }.to_not raise_error
      end
    end
    it 'raises an ArgumentError when no :byte_align is provided' do
      test_element = Class.new(BinData::Record) do
        endian :little
        uint32 :a
      end
      BinData::RegisteredClasses.register('test_element', test_element)
      expect { described_class.new(type: :test_element, byte_align: 4) }.to raise_error(ArgumentError)
    end
    it 'raises an ArgumentError when other parameters than :byte_align are provided' do
      test_element = Class.new(BinData::Array) do
        default_parameters type: :uint8
      end
      BinData::RegisteredClasses.register('test_element', test_element)
      expect { described_class.new(type: [:test_element, {other_param: 1}], byte_align: 4) }.to raise_error(ArgumentError)
    end
  end

  context 'with elements' do
    before :example do
      subject << 5
      subject << 7
    end
    counter.each do |name, position|
      let(:counter_value) { subject.to_binary_s.unpack('L'*(position+1))[position] }

      it "sets #{name} to a little endian uint32 value representing the number of elements" do
        expect(counter_value).to eq(subject.size)
      end
      it "updates #{name} when adding one element" do
        subject << 10
        expect(counter_value).to eq(subject.size)
      end

      context 'when setting a value at index greater than the current number of elements' do
        it "sets #{name} to the new number of elements" do
          subject[4] = 14
          expect(counter_value).to eq(5)
        end
      end

      context 'when reading a value at index greater than the current number of elements' do
        it "sets #{name} to the new number of elements" do
          new_element = BinData::Uint16le.new(1)
          new_element.assign(subject[4])
          expect(counter_value).to eq(5)
        end
      end

      context 'when assigning another array' do
        it "sets #{name} to the new number of elements" do
          new_array = [1,2,3]
          subject.assign(new_array)
          expect(counter_value).to eq(3)
        end
      end
    end

    context 'when reading a binary stream' do
      before :example do
        subject.read(binary_stream)
      end
      it 'has the expected size' do
        expect(subject.size).to eq(values.size)
      end
      it 'sets the new element values' do
        values.each_with_index do |value, i|
          expect(subject[i]).to eq(value)
        end
      end
      it 'has the same binary representation than the original binary stream' do
        expect(subject.to_binary_s).to eq(binary_stream)
      end
      counter.each do |name, position|
        let(:counter_value) { subject.to_binary_s.unpack('L'*(position+1))[position] }
        it "sets #{name} to the new number of elements" do
          expect(counter_value).to eq(values.size)
        end
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::FixArray do
  it 'is a BinData::Array class' do
    expect(described_class).to be < BinData::Array
  end
  it 'is an empty array by default' do
    expect(described_class.new(type: :ndr_uint16, byte_align: 2)).to eq([])
  end

  subject { described_class.new(type: :ndr_uint16, byte_align: 2, initial_length: 4) }

  it 'is an array of initial_length default elements by default' do
    expect(subject).to eq([0, 0, 0, 0])
  end

  context 'when checking if its elements have :byte_align parameter set' do
    it 'does not raise error when the :byte_align parameter is set in the element class' do
      test_element = Class.new(BinData::Record) do
        default_parameters byte_align: 4
        endian :little
        uint32 :a
      end
      BinData::RegisteredClasses.register('test_element', test_element)
      expect { described_class.new(type: :test_element, byte_align: 4) }.to_not raise_error
    end
    it 'does not raise error when the :byte_align parameter is set during instantiation' do
      test_element = Class.new(BinData::Record) do
        endian :little
        uint32 :a
      end
      BinData::RegisteredClasses.register('test_element', test_element)
      expect { described_class.new(type: [:test_element, {byte_align: 4}], byte_align: 4) }.to_not raise_error
    end
    context 'with a NDR element' do
      it 'does not raise error when the type element is a symbol' do
        expect { described_class.new(type: :ndr_uint32, byte_align: 4) }.to_not raise_error
      end
      it 'does not raise error when the type element is a class' do
        expect { described_class.new(type: RubySMB::Dcerpc::Ndr::NdrUint32, byte_align: 4) }.to_not raise_error
      end
    end
    it 'raises an ArgumentError when no :byte_align is provided' do
      test_element = Class.new(BinData::Record) do
        endian :little
        uint32 :a
      end
      BinData::RegisteredClasses.register('test_element', test_element)
      expect { described_class.new(type: :test_element, byte_align: 4) }.to raise_error(ArgumentError)
    end
    it 'raises an ArgumentError when other parameters than :byte_align are provided' do
      test_element = Class.new(BinData::Array) do
        default_parameters type: :uint8
      end
      BinData::RegisteredClasses.register('test_element', test_element)
      expect { described_class.new(type: [:test_element, {other_param: 1}], byte_align: 4) }.to raise_error(ArgumentError)
    end
  end

  context 'with elements' do
    before :example do
      subject.assign([1, 2, 3, 4])
    end
    it 'contains the expected element types' do
      expect(subject.all? {|e| e.is_a?(BinData::Uint16le)}).to be true
    end
    it 'has the expected size' do
      expect(subject.size).to eq(4)
    end

    context 'when setting a value to an element array' do
      context 'in the array bounds' do
        it 'does not raise error and sets the new value' do
          expect { subject[3] = 14 }.to_not raise_error
          expect(subject[3]).to eq(14)
        end
      end
      context 'outside of the array bounds' do
        it 'raises an error' do
          expect { subject[4] = 14 }.to raise_error(ArgumentError)
        end
      end
    end
    context 'when reading the value of an element array' do
      context 'in the array bounds' do
        it 'does not raise error and returns the value' do
          expect { subject[3] }.to_not raise_error
          expect(subject[3]).to eq(4)
        end
      end
      context 'outside of the array bounds' do
        it 'raises an error' do
          expect { subject[4] }.to raise_error(ArgumentError)
        end
      end
    end
    context 'when assigning another array' do
      context 'with the same number of elements' do
        it 'does not raise error and returns the value' do
          expect { subject.assign([5, 6, 7, 8]) }.to_not raise_error
          expect(subject).to eq([5, 6, 7, 8])
        end
      end
      context 'with more elements' do
        it 'raises an error' do
          expect { subject.assign([5, 6, 7, 8, 9]) }.to raise_error(ArgumentError)
        end
      end
      context 'with less elements' do
        it 'raises an error' do
          expect { subject.assign([5, 6, 7]) }.to raise_error(ArgumentError)
        end
      end
    end
    context 'when pushing a new element' do
      it 'raises an error' do
        expect { subject << 88 }.to raise_error(ArgumentError)
      end
    end
    context 'when unshifting a new element' do
      it 'raises an error' do
        expect { subject.unshift(88) }.to raise_error(ArgumentError)
      end
    end
    context 'when concatenating another array' do
      it 'raises an error' do
        expect { subject.concat([3,4]) }.to raise_error(ArgumentError)
      end
    end
    context 'when cheking if :byte_align parameter is set' do
      it 'does not raise error when it is set' do
        expect { described_class.new(type: :ndr_uint16, byte_align: 2, initial_length: 4) }.to_not raise_error
      end

      it 'raises an error when it is not set' do
        expect { described_class.new(type: :uint16le, initial_length: 4) }.to raise_error(ArgumentError)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::FixedByteArray do
  it 'is a RubySMB::Dcerpc::Ndr::FixArray class' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::FixArray
  end
  it 'has :byte_align parameter set to the expected value' do
    expect(described_class.default_parameters[:byte_align]).to eq(1)
  end

  subject { described_class.new(initial_length: 4) }

  it 'composed of NdrUint8 elements' do
    expect(subject[0]).to be_a( RubySMB::Dcerpc::Ndr::NdrUint8)
  end

  it 'has #initial_length elements' do
    expect(subject.size).to eq(4)
  end

  describe '#assign' do
    it 'assign elements from another array of bytes' do
      ary = [0x33, 0x43, 0x64, 0x22]
      subject.assign(ary)
      expect(subject).to eq(ary)
    end

    it 'assign bytes from string' do
      str = '_Str'
      subject.assign(str)
      expect(subject).to eq(str.bytes)
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::ConfArray do
  subject { described_class.new(type: :ndr_uint16) }
  it_behaves_like 'a BinData::Array'
  it_behaves_like 'a NDR Array', { 'max_count' => 0 } do
    let(:binary_stream) {
      "\x03\x00\x00\x00"\
      "\x09\x00"\
      "\x03\x00"\
      "\x06\x00".b
    }
    let(:values) { [9, 3, 6] }
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::VarArray do
  subject { described_class.new(type: :ndr_uint16) }
  it_behaves_like 'a BinData::Array'
  it_behaves_like 'a NDR Array', { 'actual_count' => 1 } do
    let(:binary_stream) {
      "\x00\x00\x00\x00"\
      "\x04\x00\x00\x00"\
      "\x03\x00"\
      "\x01\x00"\
      "\x07\x00"\
      "\x02\x00".b
    }
    let(:values) { [3, 1, 7, 2] }
  end
  it 'has offset always set to 0' do
    expect(subject.to_binary_s[0,4]).to eq("\x00\x00\x00\x00")
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::ConfVarArray do
  subject { described_class.new(type: :ndr_uint16) }
  it_behaves_like 'a BinData::Array'
  it_behaves_like 'a NDR Array', { 'max_count' => 0, 'actual_count' => 2 } do
    let(:binary_stream) {
      "\x04\x00\x00\x00"\
      "\x00\x00\x00\x00"\
      "\x04\x00\x00\x00"\
      "\x02\x00"\
      "\x09\x00"\
      "\x08\x00"\
      "\x05\x00".b
    }
    let(:values) { [2, 9, 8, 5] }
  end
  it 'has offset always set to 0' do
    expect(subject.to_binary_s[4,4]).to eq("\x00\x00\x00\x00")
    subject.assign([1,2])
    expect(subject.to_binary_s[4,4]).to eq("\x00\x00\x00\x00")
  end
end


#
# Strings
#

RSpec.shared_examples "a NDR String" do |conformant:, char_size:, null_terminated:|
  let(:first_char_offset) { conformant ? 12 : 8}

  it 'has :byte_align parameter set to the expected value' do
    expect(described_class.default_parameters[:byte_align]).to eq(4)
  end

  if conformant
    it_behaves_like "a Conformant Varying String", null_terminated: null_terminated
  else
    it_behaves_like "a Varying String", null_terminated: null_terminated
  end

  it 'is an empty string by default' do
    expect(subject).to eq('')
  end

  if null_terminated
    it 'has a binary representation of one NULL string terminator by default' do
      expect(subject.to_binary_s[first_char_offset..-1]).to eq("\x00" * char_size)
    end
  else
    it 'has a binary representation of an empty string by default' do
      expect(subject.to_binary_s[first_char_offset..-1]).to be_empty
    end
  end

  it 'reads itself' do
    subject.assign(value)
    expect(subject.read(subject.to_binary_s)).to eq(value)
  end

  context 'when reading another binary stream' do
    before :example do
      subject.read(binary_stream)
    end
    it 'has the expected size' do
      expect(subject.size).to eq(value.size)
    end
    it 'sets the new element values' do
      expect(subject.to_s).to eq(value)
    end
    it 'has the same binary representation than the original binary stream' do
      expect(subject.to_binary_s).to eq(binary_stream)
    end
  end
end

RSpec.shared_examples "a Conformant Varying String" do |null_terminated:|
  minimum_size = null_terminated ? 1 : 0

  it_behaves_like 'a Varying String', offset: 4, null_terminated: null_terminated

  describe '#initialize' do
    it "sets #max_count to #{minimum_size} (uint32) by default#{' (NULL terminator)' if null_terminated}" do
      expect(subject.max_count).to eq(minimum_size)
      expect(subject.to_binary_s[0, 4]).to eq([minimum_size].pack('L'))
    end
  end

  describe '#do_write' do
    it "writes #max_count corresponding to the number of elements#{' (including the NULL terminator)' if null_terminated}" do
      subject.assign(value)
      expect(subject.to_binary_s[0, 4]).to eq([value.size + minimum_size].pack('L'))
    end
  end

  describe '#do_read' do
    it "sets #max_count to the string size#{' (including the NULL terminator)' if null_terminated}" do
      subject.read(binary_stream)
      expect(subject.max_count).to eq(value.size + minimum_size)
    end
  end

  describe '#assign' do
    context 'with a string' do
      it "sets #max_count to the string length#{' (including the NULL terminator)' if null_terminated}" do
        subject.assign(value)
        expect(subject.max_count).to eq(value.length + minimum_size)
      end
    end

    context 'with a varying string' do
      it "sets #max_count to the string length#{' (including the NULL terminator)' if null_terminated}" do
        str = RubySMB::Dcerpc::Ndr::VarString.new(value)
        subject.assign(str)
        expect(subject.max_count).to eq(value.length + minimum_size)
      end
    end

    context 'with a conformant varying string' do
      it 'sets #max_count to the conformant varying string #max_count value' do
        str = RubySMB::Dcerpc::Ndr::ConfVarString.new(value)
        str.max_count = 30
        subject.assign(str)
        expect(subject.max_count).to eq(30)
      end
    end
  end

  describe '#do_num_bytes' do
    it 'give the correct total size in bytes' do
      subject.assign(value)
      expect(subject.do_num_bytes).to eq(binary_stream.size)
    end
  end
end

RSpec.shared_examples "a Varying String" do |offset: 0, null_terminated:|
  minimum_size = null_terminated ? 1 : 0

  describe '#initialize' do
    it "sets #actual_count to #{minimum_size} (uint32) by default#{' (NULL terminator)' if null_terminated}" do
      expect(subject.actual_count).to eq(minimum_size)
      expect(subject.to_binary_s[offset + 4, 4]).to eq([minimum_size].pack('L'))
    end
  end

  describe '#do_write' do
    it 'always writes 0 for "offset"' do
      expect(subject.to_binary_s[offset, 4]).to eq("\x00\x00\x00\x00".b)
      subject.assign('Test')
      expect(subject.to_binary_s[offset, 4]).to eq("\x00\x00\x00\x00".b)
    end

    it "writes #actual_count corresponding to the number of elements#{' (including the NULL terminator)' if null_terminated}" do
      subject.assign(value)
      expect(subject.to_binary_s[offset + 4, 4]).to eq([value.size + minimum_size].pack('L'))
    end
  end

  describe '#do_read' do
    it "sets #actual_count to the string size#{' (including the NULL terminator)' if null_terminated}" do
      subject.read(binary_stream)
      expect(subject.actual_count).to eq(value.size + minimum_size)
    end
  end

  describe '#assign' do
    it "sets #actual_count to the string length#{' (including the NULL terminator)' if null_terminated}" do
      subject.assign(value)
      expect(subject.actual_count).to eq(value.length + minimum_size)
    end
  end

  describe '#do_num_bytes' do
    it 'give the correct total size in bytes' do
      subject.assign(value)
      expect(subject.do_num_bytes).to eq(binary_stream.size)
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::VarString do
  subject { described_class.new }
  it 'is a BinData::String class' do
    expect(described_class).to be < BinData::String
    expect(described_class).not_to be < RubySMB::Field::String16
  end
  it_behaves_like 'a NDR String', conformant: false, char_size: 1, null_terminated: false do
    let(:binary_stream) {
      "\x00\x00\x00\x00"\
      "\x04\x00\x00\x00"\
      "\x41\x42\x43\x44".b
    }
    let(:value) { 'ABCD' }
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::VarStringz do
  subject { described_class.new }
  it 'is a BinData::Stringz class' do
    expect(described_class).to be < BinData::Stringz
    expect(described_class).not_to be < RubySMB::Field::Stringz16
  end
  it_behaves_like 'a NDR String', conformant: false, char_size: 1, null_terminated: true do
    let(:binary_stream) {
      "\x00\x00\x00\x00"\
      "\x05\x00\x00\x00"\
      "\x41\x42\x43\x44\x00".b
    }
    let(:value) { 'ABCD' }
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::VarWideString do
  subject { described_class.new }
  it 'is a RubySMB::Field::String16 class' do
    expect(described_class).to be < RubySMB::Field::String16
  end
  it_behaves_like 'a NDR String', conformant: false, char_size: 2, null_terminated: false do
    let(:binary_stream) {
      "\x00\x00\x00\x00"\
      "\x04\x00\x00\x00"\
      "\x41\x00\x42\x00\x43\x00\x44\x00".b
    }
    let(:value) { 'ABCD'.encode('utf-16le') }
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::VarWideStringz do
  subject { described_class.new }
  it 'is a RubySMB::Field::Stringz16 class' do
    expect(described_class).to be < RubySMB::Field::Stringz16
  end
  it_behaves_like 'a NDR String', conformant: false, char_size: 2, null_terminated: true do
    let(:binary_stream) {
      "\x00\x00\x00\x00"\
      "\x05\x00\x00\x00"\
      "\x41\x00\x42\x00\x43\x00\x44\x00\x00\x00".b
    }
    let(:value) { 'ABCD'.encode('utf-16le') }
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::ConfVarString do
  subject { described_class.new }
  it 'is a BinData::String class' do
    expect(described_class).to be < BinData::String
    expect(described_class).not_to be < RubySMB::Field::String16
  end
  it_behaves_like 'a NDR String', conformant: true, char_size: 1, null_terminated: false do
    let(:binary_stream) {
      "\x04\x00\x00\x00"\
      "\x00\x00\x00\x00"\
      "\x04\x00\x00\x00"\
      "\x41\x42\x43\x44".b
    }
    let(:value) { 'ABCD' }
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::ConfVarStringz do
  subject { described_class.new }
  it 'is a BinData::Stringz class' do
    expect(described_class).to be < BinData::Stringz
    expect(described_class).not_to be < RubySMB::Field::Stringz16
  end
  it_behaves_like 'a NDR String', conformant: true, char_size: 1, null_terminated: true do
    let(:binary_stream) {
      "\x05\x00\x00\x00"\
      "\x00\x00\x00\x00"\
      "\x05\x00\x00\x00"\
      "\x41\x42\x43\x44\x00".b
    }
    let(:value) { 'ABCD' }
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::ConfVarWideString do
  subject { described_class.new }
  it 'is a RubySMB::Field::String16 class' do
    expect(described_class).to be < RubySMB::Field::String16
  end
  it_behaves_like 'a NDR String', conformant: true, char_size: 2, null_terminated: false do
    let(:binary_stream) {
      "\x04\x00\x00\x00"\
      "\x00\x00\x00\x00"\
      "\x04\x00\x00\x00"\
      "\x41\x00\x42\x00\x43\x00\x44\x00".b
    }
    let(:value) { 'ABCD'.encode('utf-16le') }
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::ConfVarWideStringz do
  subject { described_class.new }
  it 'is a RubySMB::Field::Stringz16 class' do
    expect(described_class).to be < RubySMB::Field::Stringz16
  end
  it_behaves_like 'a NDR String', conformant: true, char_size: 2, null_terminated: true do
    let(:binary_stream) {
      "\x05\x00\x00\x00"\
      "\x00\x00\x00\x00"\
      "\x05\x00\x00\x00"\
      "\x41\x00\x42\x00\x43\x00\x44\x00\x00\x00".b
    }
    let(:value) { 'ABCD'.encode('utf-16le') }
  end
end


#
# Structures
#

RSpec.describe RubySMB::Dcerpc::Ndr::NdrStruct do

  describe 'Struct.method_missing' do
    context 'When validating conformant arrays' do
      let(:super_result) { double('Super method_missing result') }
      let(:super_result_array) { [super_result] }
      before :example do
        allow(super_result).to receive(:has_parameter?).and_return(true)
        allow(BinData::Record).to receive(:method_missing).and_return(super_result_array)
        allow(described_class).to receive(:validate_conformant_array)
        allow(described_class).to receive(:default_parameters).and_return({byte_align: 4})
      end
      it 'calls the superclass method_missing and returns the result' do
        expect(described_class.method_missing(1, 2)).to eq(super_result_array)
      end
      it 'performs conformant array validation if the field is an array of BinData::SanitizedField' do
        allow(super_result).to receive(:is_a?).with(BinData::SanitizedField).and_return(true)
        described_class.method_missing(1, 2)
        expect(described_class).to have_received(:validate_conformant_array).with(super_result_array)
      end
      it 'does not perform conformant array validation if the field is not an array of BinData::SanitizedField' do
        allow(super_result).to receive(:is_a?).with(BinData::SanitizedField).and_return(false)
        described_class.method_missing(1, 2)
        expect(described_class).to_not have_received(:validate_conformant_array).with(super_result_array)
      end
    end

    context 'when cheking if the fields have :byte_align parameter' do
      it 'does not raise error when it is set' do
        expect {
          Class.new(described_class) do
            default_parameters byte_align: 4
            endian :little
            ndr_uint32 :a
          end.new
        }.to_not raise_error
      end

      it 'raises an error when it is not set' do
        expect {
          Class.new(described_class) do
            endian :little
            ndr_uint32 :a
          end.new
        }.to raise_error(ArgumentError)
      end
    end
  end

  describe 'Struct.validate_conformant_array' do
    context 'with a conformant array' do
      it 'does not raise error if the array is the last member' do
        expect {
          Class.new(described_class) do
            default_parameters byte_align: 4
            endian :little

            ndr_uint32 :a
            conf_array :b, type: :ndr_uint16
          end
        }.to_not raise_error
      end
      it 'raises error if the array is not the last member' do
        expect {
          Class.new(described_class) do
            default_parameters byte_align: 4
            endian :little

            conf_array :b, type: :ndr_uint16
            ndr_uint32 :a
          end
        }.to raise_error(ArgumentError)
      end
    end

    context 'with a conformant varying array' do
      it 'does not raise error if the array is the last member' do
        expect {
          Class.new(described_class) do
            default_parameters byte_align: 4
            endian :little

            ndr_uint32     :a
            conf_var_array :b, type: :ndr_uint16
          end
        }.to_not raise_error
      end
      it 'raises error if the array is not the last member' do
        expect {
          Class.new(described_class) do
            default_parameters byte_align: 4
            endian :little

            conf_var_array :b, type: :ndr_uint16
            ndr_uint32     :a
          end
        }.to raise_error(ArgumentError)
      end
    end

    context 'with an embedded structure containing a conformant array' do
      after :example do
        BinData::RegisteredClasses.unregister('test_struct')
      end

      context 'when the embedded structure is the last member' do
        it 'does not raise error' do
          expect {
            struct_with_array = Class.new(described_class) do
              default_parameters byte_align: 4
              endian :little

              ndr_uint32     :a
              conf_var_array :b, type: :ndr_uint16
            end
            BinData::RegisteredClasses.register('test_struct', struct_with_array)
            Class.new(described_class) do
              default_parameters byte_align: 4
              endian :little

              ndr_uint32  :a
              test_struct :b
            end
          }.to_not raise_error
        end
      end

      context 'when the embedded structure is not the last member' do
        it 'raises error' do
          expect {
            struct_with_array = Class.new(described_class) do
              default_parameters byte_align: 4
              endian :little

              ndr_uint32     :a
              conf_var_array :b, type: :ndr_uint16
            end
            BinData::RegisteredClasses.register('test_struct', struct_with_array)
            Class.new(described_class) do
              default_parameters byte_align: 4
              endian :little

              test_struct :b
              ndr_uint32  :a
            end
          }.to raise_error(ArgumentError)
        end
      end
    end

    it 'is a BinData::Record class' do
      expect(described_class).to be < BinData::Record
    end

    context 'with only primitives' do
      let(:struct) do
        Class.new(described_class) do
          default_parameters byte_align: 4
          endian  :little

          ndr_uint8   :a
          ndr_uint16  :b
          ndr_uint32  :c
          char        :d
          boolean     :e
        end
      end

      it 'initializes the members to their default value' do
        expect(struct.new).to eq(a: 0, b: 0, c: 0, d: "\x00", e: false)
      end
      it 'reads itself' do
        values = {a: 44, b: 444, c: 4444, d: "T", e: true}
        struct_instance = struct.new(values)
        expect(struct.read(struct_instance.to_binary_s)).to eq(values)
      end
      context 'with values' do
        subject do
          struct.new(a: 1, b: 2, c: 3, d: "A", e: true)
        end
        it 'returns the expected member values' do
          expect(subject). to eq(a: 1, b: 2, c: 3, d: "A", e: true)
        end
        it 'outputs the expected binary representation' do
          expect(subject.to_binary_s). to eq(
            "\x01"\
            "\x00"\
            "\x02\x00"\
            "\x03\x00\x00\x00"\
            "\x41"\
            "\x00\x00\x00"\
            "\x01\x00\x00\x00".b
          )
        end
      end
    end

    context 'with fixed arrays' do
      let(:struct) do
        Class.new(described_class) do
          default_parameters byte_align: 4
          endian  :little

          ndr_uint32  :a
          fix_array   :b, type: :ndr_uint32, initial_length: 3, byte_align: 4
          ndr_uint32  :c
        end
      end

      it 'initializes the members to their default value' do
        expect(struct.new).to eq(a: 0, b: [0, 0, 0], c: 0)
      end
      it 'reads itself' do
        values = {a: 44, b: [1,2,3], c: 4444}
        struct_instance = struct.new(values)
        expect(struct.read(struct_instance.to_binary_s)).to eq(values)
      end
      context 'with values' do
        subject do
          struct.new(a: 4, b: [1,2,3], c: 5)
        end
        it 'returns the expected member values' do
          expect(subject). to eq(a: 4, b: [1,2,3], c: 5)
        end
        it 'outputs the expected binary representation' do
          expect(subject.to_binary_s). to eq(
            "\x04\x00\x00\x00"\
            "\x01\x00\x00\x00"\
            "\x02\x00\x00\x00"\
            "\x03\x00\x00\x00"\
            "\x05\x00\x00\x00"
          )
        end
      end
    end

    context 'with varying arrays' do
      let(:struct) do
        Class.new(described_class) do
          default_parameters byte_align: 4
          endian  :little

          ndr_uint32 :a
          var_array  :b, type: :ndr_uint32
          ndr_uint32 :c
        end
      end

      it 'initializes the members to their default value' do
        expect(struct.new).to eq(a: 0, b: [], c: 0)
      end
      it 'reads itself' do
        values = {a: 44, b: [1,2,3], c: 4444}
        struct_instance = struct.new(values)
        expect(struct.read(struct_instance.to_binary_s)).to eq(values)
      end
      context 'with values' do
        subject do
          struct.new(a: 4, b: [1,2,3], c: 5)
        end
        it 'returns the expected member values' do
          expect(subject). to eq(a: 4, b: [1,2,3], c: 5)
        end
        it 'outputs the expected binary representation' do
          expect(subject.to_binary_s). to eq(
            "\x04\x00\x00\x00"\
            "\x00\x00\x00\x00"\
            "\x03\x00\x00\x00"\
            "\x01\x00\x00\x00"\
            "\x02\x00\x00\x00"\
            "\x03\x00\x00\x00"\
            "\x05\x00\x00\x00"
          )
        end
      end
    end

    context 'with conformant arrays' do
      let(:struct) do
        Class.new(described_class) do
          default_parameters byte_align: 4
          endian  :little

          ndr_uint32 :a
          ndr_uint32 :b
          conf_array :c, type: :ndr_uint32
        end
      end

      it 'initializes the members to their default value' do
        expect(struct.new).to eq(a: 0, b: 0, c: [])
      end
      it 'reads itself' do
        values = {a: 44, b: 4444, c: [1,2,3]}
        struct_instance = struct.new(values)
        expect(struct.read(struct_instance.to_binary_s)).to eq(values)
      end
      context 'with values' do
        subject do
          struct.new(a: 4, b: 5, c: [1,2,3])
        end
        it 'returns the expected member values' do
          expect(subject). to eq(a: 4, b: 5, c: [1,2,3])
        end
        it 'outputs the expected binary representation' do
          expect(subject.to_binary_s). to eq(
            "\x03\x00\x00\x00"\
            "\x04\x00\x00\x00"\
            "\x05\x00\x00\x00"\
            "\x01\x00\x00\x00"\
            "\x02\x00\x00\x00"\
            "\x03\x00\x00\x00"
          )
        end
      end
    end

    context 'with a conformant varying array' do
      let(:struct) do
        Class.new(described_class) do
          default_parameters byte_align: 4
          endian  :little

          ndr_uint32     :a
          ndr_uint32     :b
          conf_var_array :c, type: :ndr_uint32
        end
      end

      it 'initializes the members to their default value' do
        expect(struct.new).to eq(a: 0, b: 0, c: [])
      end
      it 'reads itself' do
        values = {a: 44, b: 4444, c: [1,2,3]}
        struct_instance = struct.new(values)
        expect(struct.read(struct_instance.to_binary_s)).to eq(values)
      end
      context 'with values' do
        subject do
          struct.new(a: 4, b: 5, c: [1,2,3])
        end
        it 'returns the expected member values' do
          expect(subject). to eq(a: 4, b: 5, c: [1,2,3])
        end
        it 'outputs the expected binary representation' do
          expect(subject.to_binary_s). to eq(
            "\x03\x00\x00\x00"\
            "\x04\x00\x00\x00"\
            "\x05\x00\x00\x00"\
            "\x00\x00\x00\x00"\
            "\x03\x00\x00\x00"\
            "\x01\x00\x00\x00"\
            "\x02\x00\x00\x00"\
            "\x03\x00\x00\x00"
          )
        end
      end
    end

    context 'with an embedded structure containing a conformant arrays' do
      after :example do
        BinData::RegisteredClasses.unregister('test_struct')
      end

      let(:struct) do
        struct_with_array = Class.new(described_class) do
          default_parameters byte_align: 4
          endian :little

          ndr_uint32     :a
          conf_var_array :b, type: :ndr_uint32
        end
        BinData::RegisteredClasses.register('test_struct', struct_with_array)
        Class.new(described_class) do
          default_parameters byte_align: 4
          endian  :little

          ndr_uint32  :a
          ndr_uint32  :b
          test_struct :c
        end
      end

      it 'initializes the members to their default value' do
        expect(struct.new).to eq(a: 0, b: 0, c: {a: 0, b: []})
      end
      it 'reads itself' do
        values = {a: 44, b: 4444, c: {a: 5555, b: [1, 2, 3, 4]}}
        struct_instance = struct.new(values)
        expect(struct.read(struct_instance.to_binary_s)).to eq(values)
      end
      context 'with values' do
        subject do
          struct.new(a: 5, b: 6, c: {a: 7, b: [1, 2, 3, 4]})
        end
        it 'returns the expected member values' do
          expect(subject). to eq(a: 5, b: 6, c: {a: 7, b: [1, 2, 3, 4]})
        end
        it 'outputs the expected binary representation' do
          expect(subject.to_binary_s). to eq(
            "\x04\x00\x00\x00"\
            "\x05\x00\x00\x00"\
            "\x06\x00\x00\x00"\
            "\x07\x00\x00\x00"\
            "\x00\x00\x00\x00"\
            "\x04\x00\x00\x00"\
            "\x01\x00\x00\x00"\
            "\x02\x00\x00\x00"\
            "\x03\x00\x00\x00"\
            "\x04\x00\x00\x00"
          )
        end
      end
    end

  end
end


#
# Pointers
#
{
  NdrUint8Ptr: { parent_class: :NdrUint8, data: 2, binary: "\x02", size: 1 },
  NdrUint16Ptr: { parent_class: :NdrUint16, data: 3, binary: [3].pack('S'), size: 2 },
  NdrUint32Ptr: { parent_class: :NdrUint32, data: 5, binary: [5].pack('L'), size: 4 },
  NdrUint64Ptr: { parent_class: :NdrUint64, data: 7, binary: [7].pack('Q'), size: 8 },
  CharPtr: { parent_class: :Char, data: 'C', binary: 'C', size: 1 },
  BooleanPtr: { parent_class: :Boolean, data: true, binary: [1].pack('L'), size: 4 },
  StringPtr: { parent_class: :ConfVarString, data: 'Test1', binary: "#{[5].pack('L')}#{[0].pack('L')}#{[5].pack('L')}Test1", size: 4 },
  StringzPtr: { parent_class: :ConfVarStringz, data: 'Test2', binary: "#{[6].pack('L')}#{[0].pack('L')}#{[6].pack('L')}Test2\x00", size: 4 },
  WideStringPtr: { parent_class: :ConfVarWideString, data: 'Test3'.encode('utf-16le'), binary: "#{[5].pack('L')}#{[0].pack('L')}#{[5].pack('L')}#{'Test3'.encode('utf-16le').force_encoding('ASCII')}", size: 4 },
  WideStringzPtr: { parent_class: :ConfVarWideStringz, data: 'Test4'.encode('utf-16le'), binary: "#{[6].pack('L')}#{[0].pack('L')}#{[6].pack('L')}#{'Test4'.encode('utf-16le').force_encoding('ASCII')}\x00\x00", size: 4 },
  ByteArrayPtr: { parent_class: :ConfVarArray, data: [1,2,3,4], binary: "#{[4].pack('L')}#{[0].pack('L')}#{[4].pack('L')}\x01\x02\x03\x04", size: 4 },
  FileTimePtr: { parent_class: RubySMB::Field::FileTime, data: 132682503830000000, binary: [132682503830000000].pack('Q'), size: 8 }
}.each do |ndr_class, info|
  RSpec.describe(RubySMB::Dcerpc::Ndr.const_get(ndr_class)) do
    subject { described_class.new }
    let(:class_with_ref_to) do
      struct = Class.new(BinData::Record) do
        endian  :little
        uint32   :a
      end
      struct.send(described_class.bindata_name.to_sym, :b)
      struct.send(described_class.bindata_name.to_sym, :c, ref_to: :b)
      struct
    end
    let(:ref_to_instance) { class_with_ref_to.new(a: 1, b: info[:data]) }
    let(:ref_id) { [RubySMB::Dcerpc::Ndr::INITIAL_REF_ID].pack('L') }

    it 'is a RubySMB::Dcerpc::Ndr::PointerClassPlugin class' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
    end
    it 'is not a Top Level class' do
      expect(described_class).not_to be_a(RubySMB::Dcerpc::Ndr::TopLevelPlugin)
    end
    it "is a RubySMB::Dcerpc::Ndr::#{info[:parent_class]} class" do
      parent_class = if info[:parent_class].is_a?(Symbol)
                       RubySMB::Dcerpc::Ndr.const_get(info[:parent_class])
                     else
                       info[:parent_class]
                     end
      expect(described_class).to be < parent_class
    end

    it { is_expected.to respond_to :ref_id }

    describe '#initialize_instance' do
      it 'sets #ref_id to 0 by default' do
        expect(subject.ref_id).to eq(0)
      end
      it 'does not reset #ref_id to 0 when it has already be set to a value' do
        subject.ref_id = 5
        subject.initialize_instance
        expect(subject.ref_id).to eq(5)
      end
    end

    describe '#extend_top_level_class' do
      it 'does not extend to Top Level class if there is no parent in the structure' do
        subject.extend_top_level_class
        expect(described_class).not_to be_a(RubySMB::Dcerpc::Ndr::TopLevelPlugin)
      end
      it 'extends the top level structure to Top Level class' do
        struct_class = Class.new(RubySMB::Dcerpc::Ndr::NdrStruct) do
          default_parameters byte_align: 4
          endian  :little
        end
        struct_class.send(described_class.bindata_name.to_sym, :c)
        BinData::RegisteredClasses.register('test_struct', struct_class)
        test_class = Class.new(BinData::Record) do
          endian  :little
          uint32      :a
          test_struct :b
        end
        expect(ref_to_instance.is_a?(RubySMB::Dcerpc::Ndr::TopLevelPlugin)).to eq(true)
      end
    end

    describe '#snapshot' do
      it 'outputs :null by default' do
        expect(subject.snapshot).to eq(:null)
      end
      it 'outputs the referent when it refers to another Top-Level pointer' do
        expect(ref_to_instance.snapshot).to eq({a:1, b:info[:data], c:info[:data]})
      end
    end

    describe '#do_write' do
      it 'outputs 32-bit zero binary representation when it is a null pointer' do
        expect(subject.to_binary_s).to eq("\x00\x00\x00\x00".b)
      end
      it 'outputs the initial referent ID followed by the representation of the referent' do
        expect(subject.new(info[:data]).to_binary_s).to eq("#{ref_id}#{info[:binary]}".b)
      end
      it 'outputs the referent ID of the Top-Level pointer it is refering to' do
        align = (4 - (info[:binary].size % 4)) % 4
        pad = "\x00" * align
        expect(ref_to_instance.to_binary_s).to eq(
          "#{[1].pack('L')}#{ref_id}#{info[:binary]}#{pad}#{ref_id}"
        )
        expect(ref_to_instance.c.to_binary_s).to eq(ref_id)
      end
      it 'outputs the initial referent ID and the referent representaiton if it is not embedded in another constructed structure' do
        allow(subject).to receive(:parent_constructed_type).and_return(nil)
        expect(subject.new(info[:data]).to_binary_s).to eq("#{ref_id}#{info[:binary]}".b)
      end
      context 'when embedded in another constructed structure'do
        let(:embedding_struct) do
          subject.assign(info[:data])
          subject2 = described_class.new(info[:data].dup)
          RubySMB::Dcerpc::Ndr::ConfArray.new([subject, subject2], type: described_class)
        end
        before :example do
          allow(subject).to receive(:parent_constructed_type).and_return(embedding_struct)
        end

        it 'outputs the initial referent ID only' do
          expect(subject.new(info[:data]).to_binary_s).to eq("#{ref_id}".b)
        end
        it 'defers the referent representation' do
          test_instance = subject.new(info[:data])
          test_instance.to_binary_s
          expect(embedding_struct.deferred_ptrs).to eq([test_instance])
        end
        it 'correctly defers the referent after the embedding structure in the stream' do
          ref_id2 = [RubySMB::Dcerpc::Ndr::INITIAL_REF_ID + 4].pack('L')
          output_str = "#{[2].pack('L')}#{ref_id}#{ref_id2}".b
          align = (info[:size] - (output_str.size % info[:size])) % info[:size]
          output_str << "\x00".b * align
          output_str << info[:binary]
          align = (info[:size] - (output_str.size % info[:size])) % info[:size]
          output_str << "\x00".b * align
          output_str << info[:binary]
          expect(embedding_struct.to_binary_s).to eq(output_str)
        end
      end
    end

    describe '#do_read' do
      it 'reads a 32-bit zero binary representation as a null pointer' do
        expect(subject.read("\x00\x00\x00\x00".b)).to eq(:null)
      end
      it 'reads the referent ID followed by the representation of the referent' do
        ref_id = 10
        expect(subject.read("#{[ref_id].pack('L')}#{info[:binary]}")).to eq(info[:data])
        expect(subject.ref_id).to eq(ref_id)
      end
      it 'reads the referent ID of the Top-Level pointer it is refering to' do
        ref_id = 20
        align = (4 - (info[:binary].size % 4)) % 4
        pad = "\x00" * align
        binary_str = "#{[1].pack('L')}"\
                     "#{[ref_id].pack('L')}"\
                     "#{info[:binary]}"\
                     "#{pad}"\
                     "#{[ref_id].pack('L')}"
        test_instance = class_with_ref_to.read(binary_str)
        expect(test_instance.c.snapshot).to eq(info[:data])
        expect(test_instance.c.ref_id).to eq(test_instance.b.ref_id)
      end
      it 'reads the initial referent ID and the referent representaiton if it is not embedded in another constructed structure' do
        allow(subject).to receive(:parent_constructed_type).and_return(nil)
        expect(subject.read("#{ref_id}#{info[:binary]}".b)).to eq(info[:data])
        expect(subject.ref_id).to eq(RubySMB::Dcerpc::Ndr::INITIAL_REF_ID)
      end
      context 'when embedded in another constructed structure'do
        let(:test_struct) { described_class.new(info[:data].dup) }
        let(:embedding_struct) do
          subject.assign(info[:data])
          RubySMB::Dcerpc::Ndr::ConfArray.new([subject, test_struct], type: described_class)
        end
        let(:binary_str) do
          ref_id2 = [RubySMB::Dcerpc::Ndr::INITIAL_REF_ID + 4].pack('L')
          binary_str = "#{[2].pack('L')}#{ref_id}#{ref_id2}".b
          align = (info[:size] - (binary_str.size % info[:size])) % info[:size]
          binary_str << "\x00".b * align
          binary_str << info[:binary]
          align = (info[:size] - (binary_str.size % info[:size])) % info[:size]
          binary_str << "\x00".b * align
          binary_str << info[:binary]
          binary_str
        end
        it 'correctly defers the referent after the embedding structure in the stream' do
          obj = embedding_struct.read(binary_str)
          expect(obj).to eq([subject, test_struct])
        end
      end
    end

    describe '#assign' do
      it 'sets #ref_id to 0 when assigning :null' do
        subject.assign(:null)
        expect(subject.ref_id).to eq(0)
      end
      it 'assigns the value to the referent when it refers to another Top-Level pointer' do
        ref_to_instance.c = info[:data]
        expect(ref_to_instance.b).to eq(info[:data])
      end
      it 'sets #ref_id to the initial reference ID value' do
        subject.assign(info[:data])
        expect(subject.ref_id).to eq(RubySMB::Dcerpc::Ndr::INITIAL_REF_ID)
      end
      it 'does not change #ref_id when it has already been set' do
        subject.ref_id = 20
        subject.assign(info[:data])
        expect(subject.ref_id).to eq(20)
      end
    end

    describe '#alias?' do
      it 'returns true if it refers to another Top-Level pointer' do
        expect(ref_to_instance.c.is_alias?).to be true
      end
    end

    describe '#fetch_alias_referent' do
      it 'returns the referent' do
        expect(ref_to_instance.c.fetch_alias_referent).to eq(info[:data])
      end
    end

    describe '#do_num_bytes' do
      it 'returns 4 if it is a null pointer' do
        expect(subject.do_num_bytes).to eq(4)
      end
      it 'returns 4 if it refers to another Top-Level pointer' do
        expect(ref_to_instance.c.do_num_bytes).to eq(4)
      end
      it "returns #{4 + info[:binary].size} a first-instance pointer" do
        subject.assign(info[:data])
        expect(subject.do_num_bytes).to eq(4 + info[:binary].size)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::TopLevelPlugin do
  let(:struct_with_ptr) do
    Class.new(BinData::Record) do
      default_parameters byte_align: 4
      endian :little

      uint32         :b
      char_ptr       :ptr2
      ndr_uint32_ptr :ptr3
    end
  end
  let(:random_struct) do
    Class.new(RubySMB::Dcerpc::Ndr::NdrStruct) do
      default_parameters byte_align: 4

      endian          :little
      ndr_uint32      :rand1
      conf_var_string :rand2
    end
  end

  before :example do
    BinData::RegisteredClasses.register('struct_with_ptr', struct_with_ptr)
    BinData::RegisteredClasses.register('random_struct', random_struct)
  end

  context 'with a BinData structure' do
    let(:array_struct) do
      Class.new(BinData::Record) do
        endian          :little

        ndr_uint32      :a
        char_ptr        :ptr1
        struct_with_ptr :d
        ndr_uint32_ptr  :ptr4
      end
    end
    subject do
      array_struct.new(
        a: 55,
        ptr1: 'M',
        d: {
          b: 66,
          ptr2: 'A',
          ptr3: 33
        },
        ptr4: 44
      )
    end

    it 'Increments the reference IDs by 4 for each pointer' do
      ref_id = RubySMB::Dcerpc::Ndr::INITIAL_REF_ID
      output_str =
        "#{[55].pack('L')}"\
        "#{[ref_id].pack('L')}"\
        "M"\
        "\x00\x00\x00"\
        "#{[66].pack('L')}"\
        "#{[ref_id + 4].pack('L')}"\
        "A"\
        "\x00\x00\x00"\
        "#{[ref_id + 8].pack('L')}"\
        "#{[33].pack('L')}"\
        "#{[ref_id + 12].pack('L')}"\
        "#{[44].pack('L')}"
      expect(subject.to_binary_s).to eq(output_str)
    end
  end

  context 'with a NDR array and an alias pointer' do
    let(:array_struct) do
      Class.new(BinData::Record) do
        endian          :little
        uint32          :a, byte_align: 4
        char_ptr        :ptr1
        conf_array      :array1, type: :random_struct
        struct_with_ptr :d
        ndr_uint32_ptr  :ptr4, ref_to: :ptr3
      end
    end
    subject do
      array_struct.new(
        a: 55,
        ptr1: 'M',
        array1: [
          {
            rand1: 2,
            rand2: 'Test1'
          },
          {
            rand1: 6,
            rand2: 'Test2'
          }
        ],
        d: {
          b: 66,
          ptr2: 'A',
          ptr3: 33
        }
      )
    end

    it 'Increments the reference IDs by 4 for each non-alias pointer' do
      ref_id = RubySMB::Dcerpc::Ndr::INITIAL_REF_ID
      output_str =
        "#{[55].pack('L')}"\
        "#{[ref_id].pack('L')}"\
        "M"\
        "\x00\x00\x00"\
        "#{[2].pack('L')}"\
        "#{[2].pack('L')}"\
        "#{[5].pack('L')}"\
        "#{[0].pack('L')}"\
        "#{[5].pack('L')}"\
        "Test1"\
        "\x00\x00\x00"\
        "#{[6].pack('L')}"\
        "#{[5].pack('L')}"\
        "#{[0].pack('L')}"\
        "#{[5].pack('L')}"\
        "Test2"\
        "\x00\x00\x00"\
        "#{[66].pack('L')}"\
        "#{[ref_id + 4].pack('L')}"\
        "A"\
        "\x00\x00\x00"\
        "#{[ref_id + 8].pack('L')}"\
        "#{[33].pack('L')}"\
        "#{[ref_id + 8].pack('L')}"
      expect(subject.to_binary_s).to eq(output_str)
    end
  end

  context 'with a NDR array and an alias pointer positioned after the referent pointer' do
    let(:array_struct) do
      Class.new(RubySMB::Dcerpc::Ndr::ConfArray) do
        endian          :little
        uint32          :a
        char_ptr        :ptr1
        conf_array      :array1, type: :random_struct
        # :ptr3 is part of :d structure, which appears after :ptr4
        ndr_uint32_ptr  :ptr4, ref_to: :ptr3
        struct_with_ptr :d
      end
    end
    subject do
      array_struct.new([
        a: 55,
        ptr1: 'M',
        array1: [
          {
            rand1: 2,
            rand2: 'Test1'
          },
          {
            rand1: 6,
            rand2: 'Test2'
          }
        ],
        d: {
          b: 66,
          ptr2: 'A',
          ptr3: 33
        }
      ])
    end

    it 'raises an exception' do
      expect { subject.to_binary_s }.to raise_error
    end
  end
end

RSpec.describe ::BinData::NdrPointerArgProcessor do
  let(:embedding_struct) do
    Class.new(BinData::Record) do
      ndr_class :a
    end
  end

  before :example do
    ndr_class = Class.new(ref_class) do
      #default_parameters byte_align: 4
      arg_processor :ndr_pointer
    end
    BinData::RegisteredClasses.register('ndr_class', ndr_class)
  end

  context 'with a NDR structure as referent' do
    let(:ref_class) { RubySMB::Dcerpc::Ndr::NdrUint32 }
    it 'does not raise error' do
      expect { embedding_struct }.to_not raise_error
    end
  end
  context 'with a BinData structure as referent' do
    let(:ref_class) { BinData::Uint32le }

    it 'raises an error' do
      expect { embedding_struct }.to raise_error(ArgumentError)
    end
    context 'with byte_align parameter' do
      let(:embedding_struct) do
        Class.new(BinData::Record) do
          ndr_class :a, byte_align: 4
        end
      end
      it 'raises an error' do
        expect { embedding_struct }.to raise_error(ArgumentError)
      end
    end
    context 'with referent_byte_align parameter' do
      let(:embedding_struct) do
        Class.new(BinData::Record) do
          ndr_class :a, referent_byte_align: 4
        end
      end
      it 'does not raise error' do
        expect { embedding_struct }.to_not raise_error
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrContextHandle do
  it 'is a BinData::Primitive class' do
    expect(described_class).to be < BinData::Primitive
  end

  subject { described_class.new }

  it { is_expected.to respond_to :context_handle_attributes }
  it { is_expected.to respond_to :context_handle_uuid }

  context 'with #get' do
    it 'returns a hash with the default values' do
      expect(subject.get).to eq({context_handle_attributes: 0, context_handle_uuid: '00000000-0000-0000-0000-000000000000'})
    end
    it 'returns a hash with the expected values' do
      subject.assign(context_handle_attributes: 4, context_handle_uuid: '57800405-0301-3330-5566-040023007000')
      expect(subject.get).to eq({context_handle_attributes: 4, context_handle_uuid: '57800405-0301-3330-5566-040023007000'})
    end
  end

  context 'with #set' do
    context 'with a hash' do
      it 'sets the expected values' do
        subject.set({context_handle_attributes: 4, context_handle_uuid: '57800405-0301-3330-5566-040023007000'})
        expect(subject).to eq({context_handle_attributes: 4, context_handle_uuid: '57800405-0301-3330-5566-040023007000'})
      end
    end
    context 'with a NdrContextHandle object' do
      it 'sets the expected values' do
        object = described_class.new
        object.set({context_handle_attributes: 4, context_handle_uuid: '57800405-0301-3330-5566-040023007000'})
        subject.set(object)
        expect(subject).to eq({context_handle_attributes: 4, context_handle_uuid: '57800405-0301-3330-5566-040023007000'})
      end
    end
    context 'with a binary string' do
      it 'sets the expected values' do
        subject.set("\x04\x00\x00\x00\x05\x04\x80\x57\x01\x03\x30\x33\x55\x66\x04\x00\x23\x00\x70\x00")
        expect(subject).to eq({context_handle_attributes: 4, context_handle_uuid: '57800405-0301-3330-5566-040023007000'})
      end
    end
  end
end

RSpec.describe 'Alignment' do
  RSpec.shared_examples 'an aligned structure' do |align: 4, field_value:, field_binary:|
    let(:struct_obj) do
      struct_class.new(aligned_field: field_value)
    end
    it "is #{align}-bytes aligned" do
      expect(struct_obj.aligned_field.rel_offset % align).to eq(0)
    end
    it 'includes padding in its binary representation' do
      expect(struct_obj.to_binary_s).to eq("A#{"\x00" * (align - 1)}#{field_binary}".b)
    end
  end

  let(:params) { {} }
  let(:struct_class) do
    Class.new(BinData::Record) do
      endian  :little
      string  :one_byte, value: 'A'
    end
  end

  context 'in a BinData::Struct' do
    let(:params) { {} }
    before :example do
      struct_class.send(described_class.bindata_name.to_sym, :aligned_field, params)
    end

    describe RubySMB::Dcerpc::Ndr::Boolean do
      it_behaves_like(
        'an aligned structure',
        field_value: true,
        field_binary: [1].pack('L')
      )
    end

    describe RubySMB::Dcerpc::Ndr::WideChar do
      it_behaves_like(
        'an aligned structure',
        align: 2,
        field_value: 'B'.encode('utf-16le'),
        field_binary: "B\x00"
      )
    end

    describe RubySMB::Dcerpc::Ndr::Enum do
      it_behaves_like(
        'an aligned structure',
        align: 2,
        field_value: 3,
        field_binary: [3].pack('S')
      )
    end

    describe RubySMB::Dcerpc::Ndr::FixArray do
      context 'with an array of NdrUint32' do
        it_behaves_like(
          'an aligned structure',
          field_value: [1, 2, 3],
          field_binary: [1, 2, 3].pack('LLL')
        ) do
          let(:params) { {type: :ndr_uint32, initial_length: 3, byte_align: 4} }
        end
      end
      context 'with an array of NdrUint64' do
        it_behaves_like(
          'an aligned structure',
          align: 8,
          field_value: [1, 2],
          field_binary: [1, 2].pack('QQ')
        ) do
          let(:params) { {type: :ndr_uint64, initial_length: 2, byte_align: 8} }
        end
      end
    end

    describe RubySMB::Dcerpc::Ndr::ConfArray do
      context 'with an array of NdrUint32' do
        it_behaves_like(
          'an aligned structure',
          field_value: [1, 2, 3],
          field_binary: [3].pack('L') + [1, 2, 3].pack('LLL')
        ) do
          let(:params) { {type: :ndr_uint32 } }
        end
      end
      context 'with an array of NdrUint64' do
        it_behaves_like(
          'an aligned structure',
          field_value: [1, 2],
          field_binary: [2].pack('L') + [1, 2].pack('QQ')
        ) do
          let(:params) { {type: :ndr_uint64 } }
        end
      end
    end

    describe RubySMB::Dcerpc::Ndr::VarArray do
      context 'with an array of NdrUint32' do
        it_behaves_like(
          'an aligned structure',
          field_value: [1 ,2 ,3],
          field_binary: [0].pack('L') + [3].pack('L') + [1, 2, 3].pack('LLL')
        ) do
          let(:params) { {type: :ndr_uint32 } }
        end
      end
      context 'with an array of NdrUint64' do
        it_behaves_like(
          'an aligned structure',
          field_value: [1, 2],
          field_binary: [0].pack('L') + [2].pack('L') + [1, 2].pack('QQ')
        ) do
          let(:params) { {type: :ndr_uint64 } }
        end
      end
    end

    describe RubySMB::Dcerpc::Ndr::ConfVarArray do
      context 'with an array of NdrUint32' do
        it_behaves_like(
          'an aligned structure',
          field_value: [1, 2, 3],
          field_binary: [3].pack('L') + [0].pack('L') + [3].pack('L') + [1, 2, 3].pack('LLL')
        ) do
          let(:params) { {type: :ndr_uint32 } }
        end
      end
      context 'with an array of NdrUint64' do
        it_behaves_like(
          'an aligned structure',
          field_value: [1, 2],
          field_binary: [2].pack('L') + [0].pack('L') + [2].pack('L') + [1, 2].pack('QQ')
        ) do
          let(:params) { {type: :ndr_uint64 } }
        end
      end
    end

    describe RubySMB::Dcerpc::Ndr::VarString do
      it_behaves_like(
        'an aligned structure',
        field_value: "Test1",
        field_binary: [0].pack('L') + [5].pack('L') + "Test1"
      )
    end

    describe RubySMB::Dcerpc::Ndr::VarStringz do
      it_behaves_like(
        'an aligned structure',
        field_value: "Test1",
        field_binary: [0].pack('L') + [6].pack('L') + "Test1\x00"
      )
    end

    describe RubySMB::Dcerpc::Ndr::VarWideString do
      it_behaves_like(
        'an aligned structure',
        field_value: "Test1".encode('utf-16le'),
        field_binary: [0].pack('L') + [5].pack('L') + "Test1".encode('utf-16le').force_encoding('ASCII')
      )
    end

    describe RubySMB::Dcerpc::Ndr::VarWideStringz do
      it_behaves_like(
        'an aligned structure',
        field_value: "Test1".encode('utf-16le'),
        field_binary: [0].pack('L') + [6].pack('L') + "Test1\x00".encode('utf-16le').force_encoding('ASCII')
      )
    end

    describe RubySMB::Dcerpc::Ndr::ConfVarString do
      it_behaves_like(
        'an aligned structure',
        field_value: "Test1",
        field_binary: [5].pack('L') + [0].pack('L') + [5].pack('L') + "Test1"
      )
    end

    describe RubySMB::Dcerpc::Ndr::ConfVarStringz do
      it_behaves_like(
        'an aligned structure',
        field_value: "Test1",
        field_binary: [6].pack('L') + [0].pack('L') + [6].pack('L') + "Test1\x00"
      )
    end

    describe RubySMB::Dcerpc::Ndr::ConfVarWideString do
      it_behaves_like(
        'an aligned structure',
        field_value: "Test1".encode('utf-16le'),
        field_binary: [5].pack('L') + [0].pack('L') + [5].pack('L') + "Test1".encode('utf-16le').force_encoding('ASCII')
      )
    end

    describe RubySMB::Dcerpc::Ndr::ConfVarWideStringz do
      it_behaves_like(
        'an aligned structure',
        field_value: "Test1".encode('utf-16le'),
        field_binary: [6].pack('L') + [0].pack('L') + [6].pack('L') + "Test1\x00".encode('utf-16le').force_encoding('ASCII')
      )
    end

    {
      NdrUint8Ptr: { data: 2, binary: "\x02" },
      NdrUint16Ptr: { data: 3, binary: [3].pack('S') },
      NdrUint32Ptr: { data: 5, binary: [5].pack('L') },
      NdrUint64Ptr: { data: 7, binary: [7].pack('Q') },
      CharPtr: { data: 'C', binary: 'C' },
      BooleanPtr: { data: true, binary: [1].pack('L')},
      StringPtr: { data: 'Test1', binary: "#{[5].pack('L')}#{[0].pack('L')}#{[5].pack('L')}Test1" },
      StringzPtr: { data: 'Test2', binary: "#{[6].pack('L')}#{[0].pack('L')}#{[6].pack('L')}Test2\x00" },
      WideStringPtr: { data: 'Test3'.encode('utf-16le'), binary: "#{[5].pack('L')}#{[0].pack('L')}#{[5].pack('L')}#{'Test3'.encode('utf-16le').force_encoding('ASCII')}" },
      WideStringzPtr: { data: 'Test4'.encode('utf-16le'), binary: "#{[6].pack('L')}#{[0].pack('L')}#{[6].pack('L')}#{'Test4'.encode('utf-16le').force_encoding('ASCII')}\x00\x00" },
      ByteArrayPtr: { data: [1,2,3,4], binary: "#{[4].pack('L')}#{[0].pack('L')}#{[4].pack('L')}\x01\x02\x03\x04" },
      FileTimePtr: { data: 132682503830000000, binary: [132682503830000000].pack('Q') }
    }.each do |ndr_class, info|
      describe(RubySMB::Dcerpc::Ndr.const_get(ndr_class)) do
        it_behaves_like(
          'an aligned structure',
          field_value: info[:data],
          field_binary: [RubySMB::Dcerpc::Ndr::INITIAL_REF_ID].pack('L')+ info[:binary]
        )
      end
    end

    describe RubySMB::Dcerpc::Ndr::NdrContextHandle do
      it_behaves_like(
        'an aligned structure',
        field_value: { context_handle_attributes: 4, context_handle_uuid: '57800405-0301-3330-5566-040023007000' },
        field_binary: "\x04\x00\x00\x00\x05\x04\x80\x57\x01\x03\x30\x33\x55\x66\x04\x00\x23\x00\x70\x00"
      )
    end
  end

  context 'in a NDR structure' do
    describe 'Structure of mixed integers' do
      before :example do
        ndr_struct_class = Class.new(RubySMB::Dcerpc::Ndr::NdrStruct) do
          default_parameters byte_align: 4
          endian  :little

          ndr_uint32  :int_value1, byte_align: 4
          ndr_uint8   :int_value2
        end
        BinData::RegisteredClasses.register('ndr_struct_class', ndr_struct_class)
        struct_class.send(:ndr_struct_class, :aligned_field, params)
      end

      it_behaves_like(
        'an aligned structure',
        align: 4,
        field_value: { int_value1: 5, int_value2: 3 },
        field_binary: [5].pack('L') + "\x03"
      ) do
        # #byte_align is set according to the type of the largest element in
        # the structure (uint32):
        let(:params) { {byte_align: 4 } }
      end
    end
  end

  context 'in a conformant array' do
    let(:params) { {} }
    before :example do
      struct_class.send(:conf_array, :aligned_field, { :type => [ described_class, params ] } )
    end

    describe RubySMB::Dcerpc::Ndr::Boolean do
      it_behaves_like(
        'an aligned structure',
        field_value: [true, false, true],
        field_binary: [3].pack('L') + [1, 0, 1].pack('LLL')
      )
    end

    describe RubySMB::Dcerpc::Ndr::WideChar do
      it_behaves_like(
        'an aligned structure',
        field_value: 'ABC'.encode('utf-16le').chars,
        field_binary: [3].pack('L') + "A\x00B\x00C\x00"
      )
    end

    describe RubySMB::Dcerpc::Ndr::Enum do
      it_behaves_like(
        'an aligned structure',
        field_value: [1, 2, 3],
        field_binary: [3].pack('L') + [1, 2, 3].pack('SSS')
      )
    end

    describe RubySMB::Dcerpc::Ndr::FixArray do
      context 'with an array of NdrUint32' do
        it_behaves_like(
          'an aligned structure',
          field_value: [ [1, 2], [3, 4] ],
          field_binary: [2].pack('L') + [1, 2].pack('LL') + [3, 4].pack('LL')
        ) do
          let(:params) { {type: :ndr_uint32, initial_length: 2, byte_align: 4} }
        end
      end
      context 'with an array of NdrUint64' do
        it_behaves_like(
          'an aligned structure',
          field_value: [ [1, 2], [3, 4] ],
          field_binary: [2].pack('L') + [1, 2].pack('QQ') + [3, 4].pack('QQ')
        ) do
          let(:params) { {type: :ndr_uint64, initial_length: 2, byte_align: 8} }
        end
      end
    end

    describe RubySMB::Dcerpc::Ndr::ConfArray do
      context 'with an array of NdrUint32' do
        it_behaves_like(
          'an aligned structure',
          field_value: [ [1, 2], [3, 4] ],
          field_binary: [2].pack('L') + [2].pack('L') + [1, 2].pack('LL') + [2].pack('L') + [3, 4].pack('LL')
        ) do
          let(:params) { {type: :ndr_uint32} }
        end
      end
      context 'with an array of NdrUint64' do
        it_behaves_like(
          'an aligned structure',
          field_value: [ [1, 2], [3, 4] ],
          field_binary: [2].pack('L') + [2].pack('L') + [1, 2].pack('QQ') + [2].pack('L') + [3, 4].pack('QQ')
        ) do
          let(:params) { {type: :ndr_uint64} }
        end
      end
    end

    describe RubySMB::Dcerpc::Ndr::VarArray do
      context 'with an array of NdrUint32' do
        it_behaves_like(
          'an aligned structure',
          field_value: [ [1, 2], [3, 4] ],
          field_binary: [2].pack('L') + [0].pack('L') + [2].pack('L') + [1, 2].pack('LL') + [0].pack('L') + [2].pack('L') + [3, 4].pack('LL')
        ) do
          let(:params) { {type: :ndr_uint32} }
        end
      end
      context 'with an array of NdrUint64' do
        it_behaves_like(
          'an aligned structure',
          field_value: [ [1, 2], [3, 4] ],
          field_binary: [2].pack('L') + [0].pack('L') + [2].pack('L') + [1, 2].pack('QQ') + [0].pack('L') + [2].pack('L') + [3, 4].pack('QQ')
        ) do
          let(:params) { {type: :ndr_uint64} }
        end
      end
    end

    describe RubySMB::Dcerpc::Ndr::ConfVarArray do
      context 'with an array of NdrUint32' do
        it_behaves_like(
          'an aligned structure',
          field_value: [ [1, 2], [3, 4] ],
          field_binary: [2].pack('L') + [2].pack('L') + [0].pack('L') + [2].pack('L') + [1, 2].pack('LL') + [2].pack('L') + [0].pack('L') + [2].pack('L') + [3, 4].pack('LL')
        ) do
          let(:params) { {type: :ndr_uint32 } }
        end
      end
      context 'with an array of NdrUint64' do
        it_behaves_like(
          'an aligned structure',
          field_value: [ [1, 2], [3, 4] ],
          field_binary: [2].pack('L') + [2].pack('L') + [0].pack('L') + [2].pack('L') + [1, 2].pack('QQ') + [2].pack('L') + [0].pack('L') + [2].pack('L') + [3, 4].pack('QQ')
        ) do
          let(:params) { {type: :ndr_uint64} }
        end
      end
    end

    describe RubySMB::Dcerpc::Ndr::VarString do
      it_behaves_like(
        'an aligned structure',
        field_value: [ "Test1", "Test2" ],
        field_binary: [2].pack('L') + [0].pack('L') + [5].pack('L') + "Test1" + [0].pack('L') + [5].pack('L') + "Test2"
      )
    end

    describe RubySMB::Dcerpc::Ndr::VarStringz do
      it_behaves_like(
        'an aligned structure',
        field_value: [ "Test1", "Test2" ],
        field_binary: [2].pack('L') + [0].pack('L') + [6].pack('L') + "Test1\x00" + [0].pack('L') + [6].pack('L') + "Test2\x00"
      )
    end

    describe RubySMB::Dcerpc::Ndr::VarWideString do
      it_behaves_like(
        'an aligned structure',
        field_value: [ "Test1".encode('utf-16le'), "Test2".encode('utf-16le') ],
        field_binary: [2].pack('L') + [0].pack('L') + [5].pack('L') + "Test1".encode('utf-16le').force_encoding('ASCII') + [0].pack('L') + [5].pack('L') + "Test2".encode('utf-16le').force_encoding('ASCII')
      )
    end

    describe RubySMB::Dcerpc::Ndr::VarWideStringz do
      it_behaves_like(
        'an aligned structure',
        field_value: [ "Test1".encode('utf-16le'), "Test2".encode('utf-16le') ],
        field_binary: [2].pack('L') + [0].pack('L') + [6].pack('L') + "Test1\x00".encode('utf-16le').force_encoding('ASCII') + [0].pack('L') + [6].pack('L') + "Test2\x00".encode('utf-16le').force_encoding('ASCII')
      )
    end

    describe RubySMB::Dcerpc::Ndr::ConfVarString do
      it_behaves_like(
        'an aligned structure',
        field_value: [ "Test1", "Test2" ],
        field_binary: [2].pack('L') + [5].pack('L') + [0].pack('L') + [5].pack('L') + "Test1" + [5].pack('L') + [0].pack('L') + [5].pack('L') + "Test2"
      )
    end

    describe RubySMB::Dcerpc::Ndr::ConfVarStringz do
      it_behaves_like(
        'an aligned structure',
        field_value: [ "Test1", "Test2" ],
        field_binary: [2].pack('L') + [6].pack('L') + [0].pack('L') + [6].pack('L') + "Test1\x00" + [6].pack('L') + [0].pack('L') + [6].pack('L') + "Test2\x00"
      )
    end

    describe RubySMB::Dcerpc::Ndr::ConfVarWideString do
      it_behaves_like(
        'an aligned structure',
        field_value: [ "Test1".encode('utf-16le'), "Test2".encode('utf-16le') ],
        field_binary: [2].pack('L') + [5].pack('L') + [0].pack('L') + [5].pack('L') + "Test1".encode('utf-16le').force_encoding('ASCII') + [5].pack('L') + [0].pack('L') + [5].pack('L') + "Test2".encode('utf-16le').force_encoding('ASCII')
      )
    end

    describe RubySMB::Dcerpc::Ndr::ConfVarWideStringz do
      it_behaves_like(
        'an aligned structure',
        field_value: [ "Test1".encode('utf-16le'), "Test2".encode('utf-16le') ],
        field_binary: [2].pack('L') + [6].pack('L') + [0].pack('L') + [6].pack('L') + "Test1\x00".encode('utf-16le').force_encoding('ASCII') + [6].pack('L') + [0].pack('L') + [6].pack('L') + "Test2\x00".encode('utf-16le').force_encoding('ASCII')
      )
    end

    {
      NdrUint8Ptr: { data: 2, binary: "\x02", size: 1 },
      NdrUint16Ptr: { data: 3, binary: [3].pack('S'), size: 2 },
      NdrUint32Ptr: { data: 5, binary: [5].pack('L'), size: 4 },
      NdrUint64Ptr: { data: 7, binary: [7].pack('Q'), size: 8 },
      CharPtr: { data: 'C', binary: 'C', size: 1 },
      BooleanPtr: { data: true, binary: [1].pack('L'), size: 4 },
      StringPtr: {
        data: 'Test1',
        binary: "#{[5].pack('L')}#{[0].pack('L')}#{[5].pack('L')}Test1",
        size: 4
      },
      StringzPtr: {
        data: 'Test2',
        binary: "#{[6].pack('L')}#{[0].pack('L')}#{[6].pack('L')}Test2\x00",
        size: 4
      },
      WideStringPtr: {
        data: 'Test3'.encode('utf-16le'),
        binary: "#{[5].pack('L')}#{[0].pack('L')}#{[5].pack('L')}#{'Test3'.encode('utf-16le').b}",
        size: 4
      },
      WideStringzPtr: {
        data: 'Test4'.encode('utf-16le'),
        binary: "#{[6].pack('L')}#{[0].pack('L')}#{[6].pack('L')}#{'Test4'.encode('utf-16le').b}\x00\x00",
        size: 4
      },
      ByteArrayPtr: {
        data: [1,2,3,4],
        binary: "#{[4].pack('L')}#{[0].pack('L')}#{[4].pack('L')}\x01\x02\x03\x04",
        size: 4
      },
      FileTimePtr: { data: 132682503830000000, binary: [132682503830000000].pack('Q'), size: 8 }
    }.each do |ndr_class, info|
      describe(RubySMB::Dcerpc::Ndr.const_get(ndr_class)) do
        ref_id = [RubySMB::Dcerpc::Ndr::INITIAL_REF_ID].pack('L')
        ref_id2 = [RubySMB::Dcerpc::Ndr::INITIAL_REF_ID + 4].pack('L')
        binary_str = [2].pack('L') + ref_id + ref_id2
        # Embedding structure starts with 'A' + pad (4 bytes)
        current_size = 4 + binary_str.size
        align = (info[:size] - (current_size % info[:size])) % info[:size]
        binary_str << "\x00".b * align
        current_size += align
        binary_str << info[:binary]
        current_size += info[:binary].size
        align = (info[:size] - (current_size % info[:size])) % info[:size]
        binary_str << "\x00".b * align
        binary_str << info[:binary]
        it_behaves_like(
          'an aligned structure',
          field_value: [ info[:data], info[:data] ],
          field_binary: binary_str
        )
      end
    end

    describe RubySMB::Dcerpc::Ndr::NdrContextHandle do
      it_behaves_like(
        'an aligned structure',
        field_value: [
          { context_handle_attributes: 4, context_handle_uuid: '57800405-0301-3330-5566-040023007000' },
          { context_handle_attributes: 2, context_handle_uuid: '57800405-0301-3330-5566-040023007000' }
        ],
        field_binary: [2].pack('L') + "\x04\x00\x00\x00\x05\x04\x80\x57\x01\x03\x30\x33\x55\x66\x04\x00\x23\x00\x70\x00\x02\x00\x00\x00\x05\x04\x80\x57\x01\x03\x30\x33\x55\x66\x04\x00\x23\x00\x70\x00"
      )
    end
  end
end
