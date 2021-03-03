require 'ruby_smb/dcerpc/ndr'

RSpec.describe RubySMB::Dcerpc::Ndr::Boolean do
  it 'is a BinData::Uint32le class' do
    expect(described_class).to be < BinData::Uint32le
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
  it 'is a BinData::String class' do
    expect(described_class).to be < RubySMB::Field::String16
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
      expect(subject.all? {|e| e.is_a?(BinData::Uint16le)}).to be true
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
    expect(described_class.new(type: :uint16le)).to eq([])
  end

  subject { described_class.new(type: :uint16le, initial_length: 4) }

  it 'is an array of initial_length default elements by default' do
    expect(subject).to eq([0, 0, 0, 0])
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

  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::ConfArray do
  subject { described_class.new(type: :uint16le) }
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
  subject { described_class.new(type: :uint16le) }
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
  subject { described_class.new(type: :uint16le) }
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

RSpec.shared_examples "a NDR String" do |counter, first_char_offset, char_size|
  it 'is an empty string by default' do
    expect(subject).to eq('')
  end
  it 'has a binary representation of one NULL string terminator by default' do
    expect(subject.to_binary_s[first_char_offset..-1]).to eq("\x00" * char_size)
  end
  counter.each do |name, position|
    #it "has #{name} set to #{char_size} (uint32) by default (NULL terminator)" do
      #expect(subject.to_binary_s[position*4, 4]).to eq([char_size].pack('L'))
    it "has #{name} set to 1 (uint32) by default (NULL terminator)" do
      expect(subject.send(name)).to eq(1)
    end
    it "has #{name} binary representation set to 1 (uint32) by default (NULL terminator)" do
      expect(subject.to_binary_s[position*4, 4]).to eq([1].pack('L'))
    end
  end
  it 'reads itself' do
    subject.assign(str)
    expect(subject.read(subject.to_binary_s)).to eq(str)
  end

  context 'with a string' do
    before :example do
      subject.assign(str)
    end
    counter.each do |name, position|
      let(:counter_value) { subject.to_binary_s.unpack('L'*(position+1))[position] }

      it "sets #{name} to the string size in characters (including the string terminator)" do
        expect(subject.send(name)).to eq(str.size + 1)
      end
      it "sets #{name} to a little endian uint32 value representing the string size in characters (including the string terminator)" do
        #expect(counter_value).to eq(str.force_encoding('ASCII').size + char_size)
        expect(counter_value).to eq(str.size + 1)
      end

      context 'when assigning another string' do
        let(:new_str) { 'New String!' }
        before :example do
          subject.assign(new_str)
        end
        it "sets #{name} to the new number of elements" do
          expect(subject.send(name)).to eq(new_str.size + 1)
        end
        it "sets #{name} binary representation to the new number of elements" do
          #expect(counter_value).to eq((new_str.size + 1) * char_size)
          expect(counter_value).to eq(new_str.size + 1)
        end
      end
    end

    context 'when reading a binary stream' do
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
      counter.each do |name, position|
        let(:counter_value) { subject.to_binary_s.unpack('L'*(position+1))[position] }
        it "sets #{name} to the new number of elements (including the string terminator)" do
          #expect(counter_value).to eq(value.force_encoding('ASCII').size + char_size)
          expect(counter_value).to eq(value.size + 1)
        end
      end
    end
  end
end

RSpec.shared_examples "a String" do |counter, first_char_offset|
  it 'is a BinData::Stringz class' do
    expect(described_class).to be < BinData::Stringz
  end
  it_behaves_like 'a NDR String', counter, first_char_offset, 1 do
    let(:str) { 'Testing String' }
  end
end
RSpec.shared_examples "a Wide String" do |counter, first_char_offset|
  it 'is a RubySMB::Field::Stringz16 class' do
    expect(described_class).to be < RubySMB::Field::Stringz16
  end
  it_behaves_like 'a NDR String', counter, first_char_offset, 2 do
    let(:str) { 'Testing String'.encode('utf-16le') }
  end
end
RSpec.shared_examples "a conformant string" do
  describe '#assign' do
    context 'with a string' do
      it 'sets #max_count to the string length (including the NULL terminator)' do
        str = 'Testing!!!'
        subject.assign(str)
        expect(subject.max_count).to eq(str.length + 1)
      end
    end
    context 'with a varying string' do
      it 'sets #max_count to the string length (including the NULL terminator)' do
        str = RubySMB::Dcerpc::Ndr::VarString.new('Testing!!!')
        subject.assign(str)
        expect(subject.max_count).to eq(str.length + 1)
      end
    end
    context 'with a conformant varying string' do
      it 'sets #max_count to the string length (including the NULL terminator)' do
        str = described_class.new('Testing!!!')
        str.max_count = 30
        subject.assign(str)
        expect(subject.max_count).to eq(str.max_count)
      end
    end
  end
end
RSpec.shared_examples "a varying string" do |offset|
  it 'has offset always set to 0' do
    expect(subject.to_binary_s[offset,4]).to eq("\x00\x00\x00\x00".b)
    subject.assign('Test')
    expect(subject.to_binary_s[offset,4]).to eq("\x00\x00\x00\x00".b)
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::VarString do
  subject { described_class.new }
  it_behaves_like 'a String', { :actual_count => 1 }, 8 do
    let(:binary_stream) {
      "\x00\x00\x00\x00"\
      "\x05\x00\x00\x00"\
      "\x41\x42\x43\x44\x00".b
    }
    let(:value) { 'ABCD' }
  end
  it_behaves_like "a varying string", 0
end

RSpec.describe RubySMB::Dcerpc::Ndr::VarWideString do
  subject { described_class.new }
  it_behaves_like 'a Wide String', { :actual_count => 1 }, 8 do
    let(:binary_stream) {
      "\x00\x00\x00\x00"\
      "\x05\x00\x00\x00"\
      "\x41\x00\x42\x00\x43\x00\x44\x00\x00\x00".b
    }
    let(:value) { 'ABCD'.encode('utf-16le') }
  end
  it_behaves_like "a varying string", 0
end

RSpec.describe RubySMB::Dcerpc::Ndr::ConfVarString do
  subject { described_class.new }
  it_behaves_like 'a String', { :max_count => 0, :actual_count => 2 }, 12 do
    let(:binary_stream) {
      "\x05\x00\x00\x00"\
      "\x00\x00\x00\x00"\
      "\x05\x00\x00\x00"\
      "\x41\x42\x43\x44\x00".b
    }
    let(:value) { 'ABCD' }
  end
  it_behaves_like 'a varying string', 4
  it_behaves_like 'a conformant string'
end

RSpec.describe RubySMB::Dcerpc::Ndr::ConfVarWideString do
  subject { described_class.new }
  it_behaves_like 'a Wide String', { :max_count => 0, :actual_count => 2 }, 12 do
    let(:binary_stream) {
      "\x05\x00\x00\x00"\
      "\x00\x00\x00\x00"\
      "\x05\x00\x00\x00"\
      "\x41\x00\x42\x00\x43\x00\x44\x00\x00\x00".b
    }
    let(:value) { 'ABCD'.encode('utf-16le') }
  end
  it_behaves_like 'a varying string', 4
  it_behaves_like 'a conformant string'
end


#
# Structures
#

RSpec.describe RubySMB::Dcerpc::Ndr::NdrStruct do

  describe 'Struct.method_missing' do
    let(:super_result) { double('Super method_missing result') }
    let(:super_result_array) { [super_result] }
    before :example do
      allow(BinData::Record).to receive(:method_missing).and_return(super_result_array)
      allow(described_class).to receive(:validate_conformant_array)
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

  describe 'Struct.validate_conformant_array' do
    context 'with a conformant array' do
      it 'does not raise error if the array is the last member' do
        expect {
          Class.new(described_class) do
            endian :little
            uint32     :a
            conf_array :b, type: :uint16le
          end
        }.to_not raise_error
      end
      it 'raises error if the array is not the last member' do
        expect {
          Class.new(described_class) do
            endian :little
            conf_array :b, type: :uint16le
            uint32     :a
          end
        }.to raise_error(ArgumentError)
      end
    end

    context 'with a conformant varying array' do
      it 'does not raise error if the array is the last member' do
        expect {
          Class.new(described_class) do
            endian :little
            uint32         :a
            conf_var_array :b, type: :uint16le
          end
        }.to_not raise_error
      end
      it 'raises error if the array is not the last member' do
        expect {
          Class.new(described_class) do
            endian :little
            conf_var_array :b, type: :uint16le
            uint32         :a
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
              endian :little
              uint32         :a
              conf_var_array :b, type: :uint16le
            end
            BinData::RegisteredClasses.register('test_struct', struct_with_array)
            Class.new(described_class) do
              endian :little
              uint32      :a
              test_struct :b
            end
          }.to_not raise_error
        end
      end

      context 'when the embedded structure is not the last member' do
        it 'raises error' do
          expect {
            struct_with_array = Class.new(described_class) do
              endian :little
              uint32         :a
              conf_var_array :b, type: :uint16le
            end
            BinData::RegisteredClasses.register('test_struct', struct_with_array)
            Class.new(described_class) do
              endian :little
              test_struct :b
              uint32      :a
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
          endian  :little
          uint8   :a
          uint16  :b
          uint32  :c
          Char    :d
          Boolean :e
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
            "\x02\x00"\
            "\x03\x00\x00\x00"\
            "\x41"\
            "\x01\x00\x00\x00"
          )
        end
      end
    end

    context 'with fixed arrays' do
      let(:struct) do
        Class.new(described_class) do
          endian  :little
          uint32    :a
          fix_array :b, type: :uint32le, initial_length: 3
          uint32    :c
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
          endian  :little
          uint32    :a
          var_array :b, type: :uint32le
          uint32    :c
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
          endian  :little
          uint32     :a
          uint32     :b
          conf_array :c, type: :uint32le
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
          endian  :little
          uint32         :a
          uint32         :b
          conf_var_array :c, type: :uint32le
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
          endian :little
          uint32         :a
          conf_var_array :b, type: :uint32le
        end
        BinData::RegisteredClasses.register('test_struct', struct_with_array)
        Class.new(described_class) do
          endian  :little
          uint32      :a
          uint32      :b
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

