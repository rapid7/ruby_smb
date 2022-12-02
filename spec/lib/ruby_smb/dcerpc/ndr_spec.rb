require 'ruby_smb/dcerpc/ndr'

RSpec.shared_examples 'a properly aligned field in a NdrStruct' do |field, alignment|
  let(:test_struct_class) do
    klass = Class.new(RubySMB::Dcerpc::Ndr::NdrStruct) do
      default_parameters byte_align: alignment
      ndr_char :a
    end
    klass.send(field.to_sym, :test)
    klass
  end
  let(:test_struct) do
    test_struct_class.new(a: 'A', test: test_value)
  end
  let(:struct_bin) { "A#{"\x00" * (alignment - 1)}#{test_bin}".b }

  it "is always #{alignment}-bytes aligned" do
    (1..8).each do |i|
      test_struct = test_struct_class.new(a: 'A' * i, test: test_value)
      expect(test_struct.test.abs_offset % alignment).to eq(0)
    end
  end
  it 'writes the expected binary stream with the correct padding bytes' do
    expect(test_struct.to_binary_s).to eq(struct_bin)
  end
  it 'reads a padded binary stream' do
    test_struct2 = test_struct_class.read(struct_bin)
    expect(test_struct2).to eq(test_struct)
  end
  it 'reports the expected structure size' do
    expect(test_struct.num_bytes).to eq(struct_bin.size)
  end
end

RSpec.shared_examples 'a properly aligned conformant structure in a NdrStruct' do |field, alignment|
  let(:test_struct_class) do
    klass = Class.new(RubySMB::Dcerpc::Ndr::NdrStruct) do
      default_parameters byte_align: alignment
      ndr_char :a
    end
    klass.send(field.to_sym, :test)
    klass
  end
  let(:test_struct) do
    test_struct_class.new(a: 'A', test: test_value)
  end
  let(:struct_bin) do
    max_count = test_bin.slice!(0, 4)
    offset = max_count.size + 1
    align = (alignment - (offset % alignment)) % alignment
    "#{max_count}A#{"\x00" * align}#{test_bin}".b
  end

  it "is always #{alignment}-bytes aligned" do
    (1..8).each do |i|
      test_struct = test_struct_class.new(a: 'A' * i, test: test_value)
      expect(test_struct.test.abs_offset % alignment).to eq(0)
    end
  end
  it 'writes the expected binary stream with the correct padding bytes' do
    expect(test_struct.to_binary_s).to eq(struct_bin)
  end
  it 'reads a padded binary stream' do
    test_struct2 = test_struct_class.read(struct_bin)
    expect(test_struct2).to eq(test_struct)
  end
  it 'reports the expected structure size' do
    expect(test_struct.num_bytes).to eq(struct_bin.size)
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrBoolean do
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

  context 'when testing alignment in a NdrStruct' do
    it_behaves_like 'a properly aligned field in a NdrStruct', described_class.bindata_name.to_sym, 4 do
      let(:test_value) { 1 }
      let(:test_bin) { "\x01\x00\x00\x00".b }
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrChar do
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

  context 'when testing alignment in a NdrStruct' do
    it_behaves_like 'a properly aligned field in a NdrStruct', described_class.bindata_name.to_sym, 1 do
      let(:test_value) { 'B' }
      let(:test_bin) { 'B'.b }
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrWideChar do
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

  context 'when testing alignment in a NdrStruct' do
    it_behaves_like 'a properly aligned field in a NdrStruct', described_class.bindata_name.to_sym, 2 do
      let(:test_value) { 'B' }
      let(:test_bin) { "B\x00".b }
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrEnum do
  it 'is a BinData::Int16le class' do
    expect(described_class).to be < BinData::Int16le
  end
  it 'has :byte_align parameter set to the expected value' do
    expect(described_class.default_parameters[:byte_align]).to eq(2)
  end

  context 'when testing alignment in a NdrStruct' do
    it_behaves_like 'a properly aligned field in a NdrStruct', described_class.bindata_name.to_sym, 2 do
      let(:test_value) { 1 }
      let(:test_bin) { "\x01\x00".b }
    end
  end
end

{
  NdrUint8: { parent_class: :Uint8, nb_bytes: 1},
  NdrUint16: { parent_class: :Uint16le, nb_bytes: 2},
  NdrUint32: { parent_class: :Uint32le, nb_bytes: 4},
  NdrUint64: { parent_class: :Uint64le, nb_bytes: 8},
}.each do |klass, info|
  full_klass = RubySMB::Dcerpc::Ndr.const_get(klass)
  RSpec.describe(full_klass) do
    it "is a BinData::#{info[:parent_class]} class" do
      expect(described_class).to be < BinData.const_get(info[:parent_class])
    end
    it 'has :byte_align parameter set to the expected value' do
      expect(described_class.default_parameters[:byte_align]).to eq(info[:nb_bytes])
    end

    context 'when testing alignment in a NdrStruct' do
      it_behaves_like 'a properly aligned field in a NdrStruct', full_klass.bindata_name.to_sym, info[:nb_bytes] do
        let(:test_value) { 1 }
        let(:test_bin) { "\x01#{"\x00" * (info[:nb_bytes] - 1)}".b }
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrFileTime do
  it 'is a RubySMB::Field::FileTime' do
    expect(described_class).to be < RubySMB::Field::FileTime
  end
  it 'has :byte_align parameter set to the expected value' do
    expect(described_class.default_parameters[:byte_align]).to eq(4)
  end

  context 'when testing alignment in a NdrStruct' do
    it_behaves_like 'a properly aligned field in a NdrStruct', described_class.bindata_name.to_sym, 4 do
      let(:test_value) { 132820620350000000 }
      let(:test_bin) { "\x80\v\xCF\x86\xA6\xDF\xD7\x01" }
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
    expect(described_class.new(type: element_class)).to eq([])
  end

  context 'with elements' do
    it 'contains the expected element types' do
      expect(subject.all? {|e| e.is_a?(element_class)}).to be true
    end
    it 'has the expected size' do
      expect(subject.size).to eq(values.size)
    end

    context 'when setting a value at index greater than the current number of elements' do
      let(:index_offset) { 3 }
      let(:new_element) { element_class.new(values[0]) }
      before :example do
        subject[values.size + index_offset] = new_element
      end
      it 'adds elements until it reaches the new index' do
        expect(subject.size).to eq(values.size + index_offset + 1)
      end
      it 'sets the new elements to the element type default value' do
        (values.size..(index_offset - 1)).each do |i|
          expect(subject[i]).to eq(0)
        end
        expect(subject[values.size + index_offset]).to eq(new_element)
      end
    end

    context 'when getting a value at index greater than the current number of elements' do
      let(:index_offset) { 3 }
      it 'adds elements until it reaches the new index' do
        subject[values.size + index_offset]
        expect(subject.size).to eq(values.size + index_offset + 1)
      end
      it 'sets the new elements to the element type default value' do
        (values.size..index_offset).each do |i|
          expect(subject[i]).to eq(element_class.new)
        end
      end
    end

    context 'when assigning another array' do
      let(:new_array) { [values[0], values[1], values[2]] }
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

RSpec.shared_examples "a NDR Array" do |conformant:, varying:|
  let(:max_count) { subject.to_binary_s.slice(0, 4).unpack('L' * 4)[0] }
  let(:actual_count) do
    index = conformant ? 8 : 4
    subject.to_binary_s.slice(index, 4).unpack('L' * 4)[0]
  end
  let(:offset) do
    index = conformant ? 4 : 0
    subject.to_binary_s.slice(index, 4).unpack('L' * 4)[0]
  end

  if conformant
    it "has :max_count set to 0 (little endian uint32) by default" do
      empty_array = described_class.new(type: element_class)
      expect(empty_array.to_binary_s[0, 4]).to eq("\x00\x00\x00\x00")
    end
  end
  if varying
    it "has :offset and :actual_count set to 0 (little endian uint32) by default" do
      empty_array = described_class.new(type: element_class)
      # offset
      expect(empty_array.to_binary_s[0, 4]).to eq("\x00\x00\x00\x00")
      # actual_count
      expect(empty_array.to_binary_s[4, 4]).to eq("\x00\x00\x00\x00")
    end
  end
  it 'reads itself' do
    expect(described_class.new(type: element_class).read(subject.to_binary_s)).to eq(values)
  end
  it 'has :byte_align parameter set to the largest alignment of the array element type and the size information type, if any' do
    # minimum alignment is 4 bytes since arrays are prefixed with an uint32 size element for 32-bit NDR
    align = [4, element_size].max
    expect(subject.eval_parameter(:byte_align)).to eq(align)
  end

  context 'when checking if its elements have :byte_align parameter set' do
    # element independent
    it 'does not raise error when the :byte_align parameter is set in the element class' do
      test_element = Class.new(BinData::Record) do
        default_parameters byte_align: 4
        endian :little
        uint32 :a
      end
      BinData::RegisteredClasses.register('test_element', test_element)
      expect { described_class.new(type: :test_element, byte_align: 4) }.to_not raise_error
    end
    # element independent
    it 'does not raise error when the :byte_align parameter is set during instantiation' do
      test_element = Class.new(BinData::Record) do
        endian :little
        uint32 :a
      end
      BinData::RegisteredClasses.register('test_element', test_element)
      expect { described_class.new(type: [:test_element, {byte_align: 4}], byte_align: 4) }.to_not raise_error
    end
    context 'with a NDR element' do
      # element independent
      it 'does not raise error when the type element is a symbol' do
        expect { described_class.new(type: :ndr_uint32, byte_align: 4) }.to_not raise_error
      end
      # element independent
      it 'does not raise error when the type element is a class' do
        expect { described_class.new(type: RubySMB::Dcerpc::Ndr::NdrUint32, byte_align: 4) }.to_not raise_error
      end
    end
    # element independent
    it 'raises an ArgumentError when the element has no :byte_align' do
      test_element = Class.new(BinData::Record) do
        endian :little
        uint32 :a
      end
      BinData::RegisteredClasses.register('test_element', test_element)
      expect { described_class.new(type: :test_element, byte_align: 4) }.to raise_error(ArgumentError)
    end
    # element independent
    it 'raises an ArgumentError when the element has a parameter different than :byte_align' do
      test_element = Class.new(BinData::Array) do
        default_parameters type: :uint8
      end
      BinData::RegisteredClasses.register('test_element', test_element)
      expect { described_class.new(type: [:test_element, {other_param: 1}], byte_align: 4) }.to raise_error(ArgumentError)
    end
  end

  context 'with size information' do
    if conformant
      it "sets :max_count to a little endian uint32 value representing the number of elements" do
        expect(max_count).to eq(subject.size)
      end
      it "updates :max_count when adding one element" do
        subject << values[0]
        expect(max_count).to eq(subject.size)
      end
      context 'when setting a value at index greater than the current number of elements' do
        it "sets :max_count to the new number of elements" do
          index_offset = rand(10)
          subject[values.size + index_offset] = values[0]
          expect(max_count).to eq(values.size + index_offset + 1)
        end
      end
      context 'when reading a value at index greater than the current number of elements' do
        it "sets :max_count to the new number of elements" do
          index_offset = rand(10)
          subject[values.size + index_offset]
          expect(max_count).to eq(values.size + index_offset + 1)
        end
      end
      context 'when assigning another array' do
        it "sets :max_count to the new number of elements" do
          new_size = rand(10)
          new_array = new_size.times.map { values[0] }
          subject.assign(new_array)
          expect(max_count).to eq(new_size)
        end
      end
    end

    if varying
      it "sets :actual_count to a little endian uint32 value representing the number of elements" do
        expect(actual_count).to eq(subject.size)
      end
      it "updates :actual_count when adding one element" do
        subject << values[0]
        expect(actual_count).to eq(subject.size)
      end
      it 'has offset always set to 0' do
        expect(offset).to eq(0)
        subject << values[0]
        expect(offset).to eq(0)
      end
      context 'when setting a value at index greater than the current number of elements' do
        it "sets :actual_count to the new number of elements" do
          index_offset = rand(10)
          subject[values.size + index_offset] = values[0]
          expect(actual_count).to eq(values.size + index_offset + 1)
        end
      end
      context 'when reading a value at index greater than the current number of elements' do
        it "sets :actual_count to the new number of elements" do
          index_offset = rand(10)
          subject[values.size + index_offset]
          expect(actual_count).to eq(values.size + index_offset + 1)
        end
      end
      context 'when assigning another array' do
        it "sets :actual_count to the new number of elements" do
          new_size = rand(10)
          new_array = new_size.times.map { values[0] }
          subject.assign(new_array)
          expect(actual_count).to eq(new_size)
        end
      end
    end
  end

  context 'when reading a binary stream' do
    subject { described_class.new(type: element_class).read(binary_stream) }

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
    if conformant
      it "sets :max_count to the new number of elements" do
        expect(max_count).to eq(values.size)
      end
    end
    if varying
      it "sets :actual_count to the new number of elements" do
        expect(actual_count).to eq(values.size)
      end
    end
    it 'sets @read_until_index to the number of elements' do
      expect(subject.read_until_index).to eq(values.size)
    end
    context 'with an empty array' do
      let(:empty_binary_str) do
        str = ''
        str << "\x00\x00\x00\x00" if conformant
        str << "\x00\x00\x00\x00\x00\x00\x00\x00" if varying
        str
      end
      subject { described_class.new(type: element_class).read(empty_binary_str) }

      it 'is an empty array' do
        expect(subject).to eq([])
      end
      it 'sets @read_until_index to 0' do
        expect(subject.read_until_index).to eq(0)
      end
      if conformant
        it "sets :max_count to 0" do
          expect(max_count).to eq(0)
        end
      end
      if varying
        it "sets :actual_count to 0" do
          expect(actual_count).to eq(0)
        end
      end
    end
  end

  context 'when getting a binary stream' do
    it 'outputs the expected binary' do
      expect(subject.to_binary_s).to eq(binary_stream)
    end
    context 'with an empty array' do
      let(:empty_binary_str) do
        str = ''
        str << "\x00\x00\x00\x00" if conformant
        str << "\x00\x00\x00\x00\x00\x00\x00\x00" if varying
        str
      end
      subject { described_class.new(type: element_class).assign([]) }

      it 'outputs the expected binary' do
        expect(subject.to_binary_s).to eq(empty_binary_str)
      end
    end
  end

  context 'when calling #do_num_bytes' do
    it 'returns the expected number of bytes' do
      expect(subject.do_num_bytes).to eq(binary_stream.size)
    end
    context 'with NDR structures' do
      let(:array_with_struct) do
        described_class.new([{a: 2, b: 'A'}, {a: 3, b: 'B'}], type: :test_struct)
      end
      before :example do
        test_struct = Class.new(RubySMB::Dcerpc::Ndr::NdrStruct) do
          default_parameters byte_align: 4
          ndr_uint32 :a
          ndr_char   :b
        end
        BinData::RegisteredClasses.register('test_struct', test_struct)
      end

      it 'returns the expected number of bytes, including padding' do
        uint32_size = 4
        char_size = 1
        pad_size = 3
        expected_nb = (uint32_size + char_size) * 2
        expected_nb += pad_size
        expected_nb += 4 if conformant
        expected_nb += 8 if varying
        expect(array_with_struct.do_num_bytes).to eq(expected_nb)
      end
    end
  end

  {
    NdrUint8: { align: 1, data: rand(0xFF), pack: 'C' },
    NdrUint16: { align: 2, data: rand(0xFFFF), pack: 'S<' },
    NdrUint32: { align: 4, data: rand(0xFFFFFFFF), pack: 'L<' },
    NdrUint64: { align: 8, data: rand(0xFFFFFFFFFFFFFFFF), pack: 'Q<'},
    NdrChar: { align: 1, data: 'A', binary: 'A'.b },
    NdrVarString: { align: 4, data: 'AAAAA'.encode('ASCII-8BIT'), binary: "#{[0].pack('L')}#{[5].pack('L')}AAAAA".b},
    NdrVarStringz: { align: 4, data: 'AAAAA'.encode('ASCII-8BIT'), binary: "#{[0].pack('L')}#{[6].pack('L')}AAAAA\x00".b},
    NdrVarWideString: { align: 4, data: 'AAAAA'.encode('UTF-16LE'), binary: "#{[0].pack('L')}#{[5].pack('L')}A\x00A\x00A\x00A\x00A\x00".b},
    NdrVarWideStringz: { align: 4, data: 'AAAAA'.encode('UTF-16LE'), binary: "#{[0].pack('L')}#{[6].pack('L')}A\x00A\x00A\x00A\x00A\x00\x00\x00".b},
  }.each do |klass, info|
    context "when it is embedded in a NDR structure and preceeded by a #{klass}" do
      let(:field_class) { RubySMB::Dcerpc::Ndr.const_get(klass) }
      let(:field_obj) { field_class.new(info[:data]) }
      let(:embedded_struct) do
        byte_align = struct_max_align
        embedded_struct = Class.new(RubySMB::Dcerpc::Ndr::NdrStruct) do
          default_parameters(byte_align: byte_align)
        end
        embedded_struct.send(field_class.bindata_name.to_sym, :a)
        embedded_struct
      end

      context 'directly as an array' do
        before :example do
          embedded_struct.send(described_class.bindata_name.to_sym, :ary, type: element_class)
        end
        let(:array_max_align) { (varying && element_size < 4) ? 4 : element_size }
        let(:struct_max_align) { [array_max_align, info[:align]].max }
        let(:test_instance) { embedded_struct.new(a: field_obj, ary: values) }
        let(:binary_str) do
          binary_str = "".b
          if conformant
            binary_str << binary_stream.slice!(0, 4)
          end
          pad_length = (struct_max_align - (binary_str.size % struct_max_align)) % struct_max_align
          binary_str << "\x00" * pad_length
          if info[:data].is_a?(String)
            binary_str << info[:binary]
          else
            binary_str << "#{[info[:data]].pack(info[:pack])}"
          end
          if varying
            pad_length = (array_max_align - (binary_str.size % array_max_align)) % array_max_align
            binary_str << "\x00" * pad_length
            binary_str << binary_stream.slice!(0, 8)
          end
          pad_length = (element_size - (binary_str.size % element_size)) % element_size
          binary_str << "\x00" * pad_length
          binary_str << bin_values
          binary_str
        end

        context 'when writing the stream of bytes' do
          it 'outputs the expect binary' do
            expect(test_instance.to_binary_s).to eq(binary_str)
          end
        end

        context 'when reading a stream of bytes' do
          it 'outputs the expected structure' do
            expect(embedded_struct.read(binary_str)).to eq({ a: info[:data], ary: values })
          end
        end

        context 'when calling #num_bytes' do
          it 'outputs the expected number of bytes' do
            expect(test_instance.num_bytes).to eq(binary_str.size)
          end
        end
      end

      context 'as a pointer to an array' do
        before :example do
          array_ptr = Class.new(described_class) do
            extend RubySMB::Dcerpc::Ndr::PointerClassPlugin
          end
          BinData::RegisteredClasses.register('test_array_ptr', array_ptr)
          embedded_struct.send(:test_array_ptr, :ary_ptr, type: element_class)
        end
        let(:struct_max_align) { [4, info[:align]].max }
        let(:test_instance) { embedded_struct.new(a: field_obj, ary_ptr: values) }
        let(:binary_str) do
          binary_str = "".b
          if info[:data].is_a?(String)
            binary_str << info[:binary]
          else
            binary_str << "#{[info[:data]].pack(info[:pack])}"
          end
          pad_length = (4 - (binary_str.size % 4)) % 4
          binary_str << "\x00" * pad_length
          ref_id = [RubySMB::Dcerpc::Ndr::INITIAL_REF_ID].pack('L<')
          binary_str << ref_id
          if conformant
            binary_str << binary_stream.slice!(0, 4)
          end
          if varying
            binary_str << binary_stream.slice!(0, 8)
          end
          pad_length = (element_size - (binary_str.size % element_size)) % element_size
          binary_str << "\x00" * pad_length
          binary_str << bin_values
          binary_str
        end

        context 'when writing the stream of bytes' do
          it 'outputs the expect binary' do
            expect(test_instance.to_binary_s).to eq(binary_str)
          end
        end

        context 'when reading a stream of bytes' do
          it 'outputs the expected structure' do
            expect(embedded_struct.read(binary_str)).to eq({ a: info[:data], ary_ptr: values })
          end
        end

        context 'when calling #num_bytes' do
          it 'outputs the expected number of bytes' do
            expect(test_instance.num_bytes).to eq(binary_str.size)
          end
        end
      end

      context 'embedded in another structure' do
        before :example do
          byte_align = struct_max_align
          embedded_struct2 = Class.new(RubySMB::Dcerpc::Ndr::NdrStruct) do
            default_parameters(byte_align: byte_align)
          end
          embedded_struct2.send(field_class.bindata_name.to_sym, :a)
          embedded_struct2.send(described_class.bindata_name.to_sym, :ary, type: element_class)
          BinData::RegisteredClasses.register('embedded_struct_2nd_lvl', embedded_struct2)
          embedded_struct.send(:embedded_struct_2nd_lvl, :struct2)
        end
        let(:array_max_align) { (varying && element_size < 4) ? 4 : element_size }
        let(:struct2_max_align) { [array_max_align, info[:align]].max }
        let(:struct_max_align) { [struct2_max_align, info[:align]].max }
        let(:test_instance) { embedded_struct.new(a: field_obj, struct2: { a: field_obj, ary: values }) }
        let(:binary_str) do
          binary_str = "".b
          if conformant
            binary_str << binary_stream.slice!(0, 4)
          end
          # a
          pad_length = (struct_max_align - (binary_str.size % struct_max_align)) % struct_max_align
          binary_str << "\x00" * pad_length
          if info[:data].is_a?(String)
            binary_str << info[:binary]
          else
            binary_str << "#{[info[:data]].pack(info[:pack])}"
          end
          # struct2.a
          pad_length = (struct2_max_align - (binary_str.size % struct2_max_align)) % struct2_max_align
          binary_str << "\x00" * pad_length
          if info[:data].is_a?(String)
            binary_str << info[:binary]
          else
            binary_str << "#{[info[:data]].pack(info[:pack])}"
          end
          # struct2.ary
          if varying
            pad_length = (array_max_align - (binary_str.size % array_max_align)) % array_max_align
            binary_str << "\x00" * pad_length
            binary_str << binary_stream.slice!(0, 8)
          end
          pad_length = (element_size - (binary_str.size % element_size)) % element_size
          binary_str << "\x00" * pad_length
          binary_str << bin_values
          binary_str
        end

        context 'when writing the stream of bytes' do
          it 'outputs the expect binary' do
            expect(test_instance.to_binary_s).to eq(binary_str)
          end
        end

        context 'when reading a stream of bytes' do
          it 'outputs the expected structure' do
            expect(embedded_struct.read(binary_str)).to eq({ a: field_obj, struct2: { a: field_obj, ary: values } })
          end
        end

        context 'when calling #num_bytes' do
          it 'outputs the expected number of bytes' do
            expect(test_instance.num_bytes).to eq(binary_str.size)
          end
        end
      end

      unless conformant
        {
          NdrUint8:  { size: 1 },
          NdrUint16: { size: 2 },
          NdrUint32: { size: 4 },
          NdrUint64: { size: 8 }
        }.each do |klass2, info2|
          context "directly as an array and followed by a #{klass2}" do
            before :example do
              embedded_struct.send(described_class.bindata_name.to_sym, :ary, type: element_class)
              embedded_struct.send(field_class2.bindata_name.to_sym, :b)
            end
            let(:field_class2) { RubySMB::Dcerpc::Ndr.const_get(klass2) }
            let(:field_obj2) { field_class2.new(rand(0xFF)) }
            let(:array_max_align) { element_size < 4 ? 4 : element_size }
            let(:struct_max_align) { [array_max_align, info[:align], info2[:size]].max }
            let(:test_instance) { embedded_struct.new(a: field_obj, ary: values, b: field_obj2) }
            let(:binary_str) do
              binary_str = "".b
              # a
              if info[:data].is_a?(String)
                binary_str << info[:binary]
              else
                binary_str << "#{[info[:data]].pack(info[:pack])}"
              end
              # ary
              pad_length = (array_max_align - (binary_str.size % array_max_align)) % array_max_align
              binary_str << "\x00" * pad_length
              binary_str << binary_stream.slice!(0, 8)
              pad_length = (element_size - (binary_str.size % element_size)) % element_size
              binary_str << "\x00" * pad_length
              binary_str << bin_values
              # b
              pad_length = (info2[:size] - (binary_str.size % info2[:size])) % info2[:size]
              binary_str << "\x00" * pad_length
              binary_str << field_obj2.to_binary_s
              binary_str
            end

            context 'when writing the stream of bytes' do
              it 'outputs the expect binary' do
                expect(test_instance.to_binary_s).to eq(binary_str)
              end
            end

            context 'when reading a stream of bytes' do
              it 'outputs the expected structure' do
                expect(embedded_struct.read(binary_str)).to eq({ a: info[:data], ary: values, b: field_obj2.to_i })
              end
            end

            context 'when calling #num_bytes' do
              it 'outputs the expected number of bytes' do
                expect(test_instance.num_bytes).to eq(binary_str.size)
              end
            end
          end
        end
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::NdrFixArray do
  it 'is a BinData::Array class' do
    expect(described_class).to be < BinData::Array
  end
  it 'is an empty array by default' do
    expect(described_class.new(type: :ndr_uint16, byte_align: 2)).to eq([])
  end

  subject { described_class.new(type: :ndr_uint16, byte_align: 2, initial_length: 4) }

  it 'is an array of initial_length default elements' do
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

RSpec.describe RubySMB::Dcerpc::Ndr::NdrFixedByteArray do
  it 'is a RubySMB::Dcerpc::Ndr::NdrFixArray class' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrFixArray
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

{
  NdrUint8: { size: 1, data: rand(0xFF), pack: 'C' },
  NdrUint16: { size: 2, data: rand(0xFFFF), pack: 'S<' },
  NdrUint32: { size: 4, data: rand(0xFFFFFFFF), pack: 'L<' },
  NdrUint64: { size: 8, data: rand(0xFFFFFFFFFFFFFFFF), pack: 'Q<'},
  NdrChar: {  size: 1, data: 'A', binary: 'A'.b },
  NdrVarString: { size: 4, data: 'AAAAA'.encode('ASCII-8BIT'), binary: "#{[0].pack('L')}#{[5].pack('L')}AAAAA".b},
  NdrVarStringz: { size: 4, data: 'AAAAA'.encode('ASCII-8BIT'), binary: "#{[0].pack('L')}#{[6].pack('L')}AAAAA\x00".b},
  NdrVarWideString: { size: 4, data: 'AAAAA'.encode('UTF-16LE'), binary: "#{[0].pack('L')}#{[5].pack('L')}A\x00A\x00A\x00A\x00A\x00".b},
  NdrVarWideStringz: { size: 4, data: 'AAAAA'.encode('UTF-16LE'), binary: "#{[0].pack('L')}#{[6].pack('L')}A\x00A\x00A\x00A\x00A\x00\x00\x00".b},
}.each do |klass, info|
  RSpec.describe "NDR Array with #{klass}" do
    let(:element_size) { info[:size] }
    let(:element_class) { RubySMB::Dcerpc::Ndr.const_get(klass) }
    let(:values) { rand(3..16).times.map { info[:data] } }
    #let(:values) { [0xFF, 0xFF, 0xFF, 0xFF] }
    let(:bin_values) do
      if info[:data].is_a?(String)
        info[:binary] * values.size
      else
        values.map { |e| [e].pack(info[:pack]) }.join
      end
    end
    let(:binary_stream) do
      pad_length = (element_size - (size_info.size % element_size)) % element_size
      "#{size_info}#{"\x00" * pad_length}#{bin_values}".b
    end
    subject { described_class.new(values, type: element_class) }

    describe RubySMB::Dcerpc::Ndr::NdrConfArray do
      let(:size_info) { [values.size].pack('L<') }
      it_behaves_like 'a BinData::Array'
      it_behaves_like 'a NDR Array', conformant: true, varying: false
    end

    describe RubySMB::Dcerpc::Ndr::NdrVarArray do
      let(:size_info) { "\x00\x00\x00\x00#{[values.size].pack('L<')}" }
      it_behaves_like 'a BinData::Array'
      it_behaves_like 'a NDR Array', conformant: false, varying: true
    end

    describe RubySMB::Dcerpc::Ndr::NdrConfVarArray do
      let(:size_info) { "#{[values.size].pack('L<')}\x00\x00\x00\x00#{[values.size].pack('L<')}" }
      it_behaves_like 'a BinData::Array'
      it_behaves_like 'a NDR Array', conformant: true, varying: true
    end
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

  it 'has a binary representation of an empty string by default' do
    expect(subject.to_binary_s[first_char_offset..-1]).to be_empty
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
    it "sets #max_count to 0 (uint32) by default" do
      expect(subject.max_count).to eq(0)
      expect(subject.to_binary_s[0, 4]).to eq([0].pack('L'))
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
        case subject
        when RubySMB::Field::Stringz16
          str = RubySMB::Dcerpc::Ndr::NdrVarWideStringz.new(value)
        when RubySMB::Field::String16
          str = RubySMB::Dcerpc::Ndr::NdrVarWideString.new(value)
        when BinData::Stringz
          str = RubySMB::Dcerpc::Ndr::NdrVarStringz.new(value)
        when BinData::String
          str = RubySMB::Dcerpc::Ndr::NdrVarString.new(value)
        end
        subject.assign(str)
        expect(subject.max_count).to eq(value.length + minimum_size)
      end
    end

    context 'with a conformant varying string' do
      it 'sets #max_count to the conformant varying string #max_count value' do
        case subject
        when RubySMB::Field::Stringz16
          str = RubySMB::Dcerpc::Ndr::NdrConfVarWideStringz.new(value)
        when RubySMB::Field::String16
          str = RubySMB::Dcerpc::Ndr::NdrConfVarWideString.new(value)
        when BinData::Stringz
          str = RubySMB::Dcerpc::Ndr::NdrConfVarStringz.new(value)
        when BinData::String
          str = RubySMB::Dcerpc::Ndr::NdrConfVarString.new(value)
        end
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
    it 'sets #actual_count to 0 (uint32) by default' do
      expect(subject.actual_count).to eq(0)
      expect(subject.to_binary_s[offset + 4, 4]).to eq([0].pack('L'))
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

RSpec.describe RubySMB::Dcerpc::Ndr::NdrVarString do
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

RSpec.describe RubySMB::Dcerpc::Ndr::NdrVarStringz do
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

RSpec.describe RubySMB::Dcerpc::Ndr::NdrVarWideString do
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

RSpec.describe RubySMB::Dcerpc::Ndr::NdrVarWideStringz do
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

RSpec.describe RubySMB::Dcerpc::Ndr::NdrConfVarString do
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

RSpec.describe RubySMB::Dcerpc::Ndr::NdrConfVarStringz do
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

RSpec.describe RubySMB::Dcerpc::Ndr::NdrConfVarWideString do
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

RSpec.describe RubySMB::Dcerpc::Ndr::NdrConfVarWideStringz do
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

      it 'does not raise error when the field is a BinData:Bit*' do
        expect {
          Class.new(described_class) do
            default_parameters byte_align: 4
            endian :little
            bit2 :a
          end.new
        }.to_not raise_error
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

            ndr_uint32     :a
            ndr_conf_array :b, type: :ndr_uint16
          end
        }.to_not raise_error
      end
      it 'raises error if the array is not the last member' do
        expect {
          Class.new(described_class) do
            default_parameters byte_align: 4
            endian :little

            ndr_conf_array :b, type: :ndr_uint16
            ndr_uint32     :a
          end
        }.to raise_error(ArgumentError)
      end
      it 'does not raise error if the array is not the last member of a non NdrStruct' do
        expect {
          Class.new(BinData::Record) do
            default_parameters byte_align: 4
            endian :little

            ndr_conf_array :b, type: :ndr_uint16
            ndr_uint32     :a
          end
        }.to_not raise_error
      end
    end

    context 'with a conformant varying array' do
      it 'does not raise error if the array is the last member' do
        expect {
          Class.new(described_class) do
            default_parameters byte_align: 4
            endian :little

            ndr_uint32         :a
            ndr_conf_var_array :b, type: :ndr_uint16
          end
        }.to_not raise_error
      end
      it 'raises error if the array is not the last member' do
        expect {
          Class.new(described_class) do
            default_parameters byte_align: 4
            endian :little

            ndr_conf_var_array :b, type: :ndr_uint16
            ndr_uint32         :a
          end
        }.to raise_error(ArgumentError)
      end
    end

    context 'with a conformant varying string' do
      it 'does not raise error if the string is the last member' do
        expect {
          Class.new(described_class) do
            default_parameters byte_align: 4
            endian :little

            ndr_uint32          :a
            ndr_conf_var_string :b
          end
        }.to_not raise_error
      end
      it 'raises error if the string is not the last member' do
        expect {
          Class.new(described_class) do
            default_parameters byte_align: 4
            endian :little

            ndr_conf_var_string :b
            ndr_uint32          :a
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

              ndr_uint32         :a
              ndr_conf_var_array :b, type: :ndr_uint16
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

              ndr_uint32         :a
              ndr_conf_var_array :b, type: :ndr_uint16
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
        ndr_char    :d
        ndr_boolean :e
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
        expect(subject).to eq(a: 1, b: 2, c: 3, d: "A", e: true)
      end
      it 'outputs the expected binary representation' do
        binary =  "\x01"             # a
        binary << "\x00"             # pad
        binary << "\x02\x00"         # b
        binary << "\x03\x00\x00\x00" # c
        binary << "\x41"             # d
        binary << "\x00\x00\x00"     # pad
        binary << "\x01\x00\x00\x00" # e
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with pointers' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint8      :a
        ndr_uint16_ptr :b
        ndr_uint32     :c
        ndr_char_ptr   :d
        ndr_boolean    :e
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: :null, c: 0, d: :null, e: false)
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
        expect(subject).to eq(a: 1, b: 2, c: 3, d: "A", e: true)
      end
      it 'outputs the expected binary representation' do
        binary =  "\x01"             # a
        binary << "\x00\x00\x00"     # pad
        binary << "\x01\x00\x00\x00" # b.ref_id
        binary << "\x03\x00\x00\x00" # c
        binary << "\x02\x00\x00\x00" # d.ref_id
        binary << "\x01\x00\x00\x00" # e
        binary << "\x02\x00"         # deferred b
        binary << "\x41"             # deferred d
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with fixed arrays' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint32    :a
        ndr_fix_array :b, type: :ndr_uint32, initial_length: 3, byte_align: 4
        ndr_uint32    :c
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
        expect(subject).to eq(a: 4, b: [1,2,3], c: 5)
      end
      it 'outputs the expected binary representation' do
        binary =  "\x04\x00\x00\x00" # a
        binary << "\x01\x00\x00\x00" # b[0]
        binary << "\x02\x00\x00\x00" # b[1]
        binary << "\x03\x00\x00\x00" # b[2]
        binary << "\x05\x00\x00\x00" # c
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with fixed arrays containing pointers' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint32    :a
        ndr_fix_array :b, type: :ndr_uint32_ptr, initial_length: 3, byte_align: 4
        ndr_uint32    :c
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: [:null, :null, :null], c: 0)
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
        expect(subject).to eq(a: 4, b: [1,2,3], c: 5)
      end
      it 'outputs the expected binary representation' do
        binary =  "\x04\x00\x00\x00" # a
        binary << "\x01\x00\x00\x00" # b[0].ref_id
        binary << "\x02\x00\x00\x00" # b[1].ref_id
        binary << "\x03\x00\x00\x00" # b[2].ref_id
        binary << "\x05\x00\x00\x00" # c
        binary << "\x01\x00\x00\x00" # b[0]
        binary << "\x02\x00\x00\x00" # b[1]
        binary << "\x03\x00\x00\x00" # b[2]
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with varying arrays' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint32    :a
        ndr_var_array :b, type: :ndr_uint32
        ndr_uint32    :c
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
        expect(subject).to eq(a: 4, b: [1,2,3], c: 5)
      end
      it 'outputs the expected binary representation' do
        binary =  "\x04\x00\x00\x00" # a
        binary << "\x00\x00\x00\x00" # array offset
        binary << "\x03\x00\x00\x00" # array actual_count
        binary << "\x01\x00\x00\x00" # b[0]
        binary << "\x02\x00\x00\x00" # b[1]
        binary << "\x03\x00\x00\x00" # b[2]
        binary << "\x05\x00\x00\x00" # c
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with varying arrays containing pointers' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint32    :a
        ndr_var_array :b, type: :ndr_uint32_ptr
        ndr_uint32    :c
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
        expect(subject).to eq(a: 4, b: [1,2,3], c: 5)
      end
      it 'outputs the expected binary representation' do
        binary =  "\x04\x00\x00\x00" # a
        binary << "\x00\x00\x00\x00" # array offset
        binary << "\x03\x00\x00\x00" # array actual_count
        binary << "\x01\x00\x00\x00" # b[0].ref_id
        binary << "\x02\x00\x00\x00" # b[1].ref_id
        binary << "\x03\x00\x00\x00" # b[2].ref_id
        binary << "\x05\x00\x00\x00" # c
        binary << "\x01\x00\x00\x00" # deferred b[0]
        binary << "\x02\x00\x00\x00" # deferred b[1]
        binary << "\x03\x00\x00\x00" # deferred b[2]
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with conformant arrays' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint32     :a
        ndr_uint32     :b
        ndr_conf_array :c, type: :ndr_uint32
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
        expect(subject).to eq(a: 4, b: 5, c: [1,2,3])
      end
      it 'outputs the expected binary representation' do
        binary =  "\x03\x00\x00\x00" # array max_count
        binary << "\x04\x00\x00\x00" # a
        binary << "\x05\x00\x00\x00" # b
        binary << "\x01\x00\x00\x00" # c[0]
        binary << "\x02\x00\x00\x00" # c[1]
        binary << "\x03\x00\x00\x00" # c[2]
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with conformant arrays containing pointers' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint32     :a
        ndr_uint32     :b
        ndr_conf_array :c, type: :ndr_uint32_ptr
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
        expect(subject).to eq(a: 4, b: 5, c: [1,2,3])
      end
      it 'outputs the expected binary representation' do
        binary =  "\x03\x00\x00\x00" # array max_count
        binary << "\x04\x00\x00\x00" # a
        binary << "\x05\x00\x00\x00" # b
        binary << "\x01\x00\x00\x00" # c[0].ref_id
        binary << "\x02\x00\x00\x00" # c[1].ref_id
        binary << "\x03\x00\x00\x00" # c[2].ref_id
        binary << "\x01\x00\x00\x00" # c[0]
        binary << "\x02\x00\x00\x00" # c[1]
        binary << "\x03\x00\x00\x00" # c[2]
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with a conformant varying array' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint32         :a
        ndr_uint32         :b
        ndr_conf_var_array :c, type: :ndr_uint32
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
        expect(subject).to eq(a: 4, b: 5, c: [1,2,3])
      end
      it 'outputs the expected binary representation' do
        binary =  "\x03\x00\x00\x00" # array max_count
        binary << "\x04\x00\x00\x00" # a
        binary << "\x05\x00\x00\x00" # b
        binary << "\x00\x00\x00\x00" # array offset
        binary << "\x03\x00\x00\x00" # array actual_count
        binary << "\x01\x00\x00\x00" # c[0]
        binary << "\x02\x00\x00\x00" # c[1]
        binary << "\x03\x00\x00\x00" # c[2]
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with a conformant varying array containing pointers' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint32         :a
        ndr_uint32         :b
        ndr_conf_var_array :c, type: :ndr_uint32_ptr
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
        expect(subject).to eq(a: 4, b: 5, c: [1,2,3])
      end
      it 'outputs the expected binary representation' do
        binary =  "\x03\x00\x00\x00" # array max_count
        binary << "\x04\x00\x00\x00" # a
        binary << "\x05\x00\x00\x00" # c
        binary << "\x00\x00\x00\x00" # array offset
        binary << "\x03\x00\x00\x00" # array actual_count
        binary << "\x01\x00\x00\x00" # b[0].ref_id
        binary << "\x02\x00\x00\x00" # b[1].ref_id
        binary << "\x03\x00\x00\x00" # b[2].ref_id
        binary << "\x01\x00\x00\x00" # deferred b[0]
        binary << "\x02\x00\x00\x00" # deferred b[1]
        binary << "\x03\x00\x00\x00" # deferred b[2]
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with an embedded structure containing a fixed array' do
    after :example do
      BinData::RegisteredClasses.unregister('test_struct')
    end

    let(:struct) do
      struct_with_array = Class.new(described_class) do
        default_parameters byte_align: 4
        endian :little

        ndr_uint16    :a
        ndr_fix_array :b, type: :ndr_uint32, initial_length: 3, byte_align: 4
        ndr_uint16    :c
      end
      BinData::RegisteredClasses.register('test_struct', struct_with_array)
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint16  :a
        ndr_uint16  :b
        test_struct :c
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: 0, c: {a: 0, b: [0, 0 ,0], c: 0})
    end
    it 'reads itself' do
      values = {a: 44, b: 4444, c: {a: 5555, b: [1, 2, 3], c: 77}}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 5, b: 6, c: {a: 7, b: [1, 2, 3], c: 8})
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 5, b: 6, c: {a: 7, b: [1, 2, 3], c: 8})
      end
      it 'outputs the expected binary representation' do
        binary =  "\x05\x00" # a
        binary << "\x06\x00" # b
        binary << "\x07\x00" # c.a
        binary << "\x00\x00" # pad
        binary << "\x01\x00\x00\x00" # c.b[0]
        binary << "\x02\x00\x00\x00" # c.b[1]
        binary << "\x03\x00\x00\x00" # c.b[2]
        binary << "\x08\x00" # c.c
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with an embedded structure containing a fixed array of pointers' do
    after :example do
      BinData::RegisteredClasses.unregister('test_struct')
    end

    let(:struct) do
      struct_with_array = Class.new(described_class) do
        default_parameters byte_align: 4
        endian :little

        ndr_uint16    :a
        ndr_fix_array :b, type: :ndr_uint32_ptr, initial_length: 3, byte_align: 4
        ndr_uint16    :c
      end
      BinData::RegisteredClasses.register('test_struct', struct_with_array)
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint16  :a
        ndr_uint16  :b
        test_struct :c
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: 0, c: {a: 0, b: [:null, :null ,:null], c: 0})
    end
    it 'reads itself' do
      values = {a: 44, b: 4444, c: {a: 5555, b: [1, 2, 3], c: 77}}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 5, b: 6, c: {a: 7, b: [1, 2, 3], c: 8})
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 5, b: 6, c: {a: 7, b: [1, 2, 3], c: 8})
      end
      it 'outputs the expected binary representation' do
        binary =  "\x05\x00"         # a
        binary << "\x06\x00"         # b
        binary << "\x07\x00"         # c.a
        binary << "\x00\x00"         # pad
        binary << "\x01\x00\x00\x00" # c.b[0].ref_id
        binary << "\x02\x00\x00\x00" # c.b[1].ref_id
        binary << "\x03\x00\x00\x00" # c.b[2].ref_id
        binary << "\x08\x00"         # c.c
        binary << "\x00\x00"         # pad
        binary << "\x01\x00\x00\x00" # deferred c.b[0]
        binary << "\x02\x00\x00\x00" # deferred c.b[1]
        binary << "\x03\x00\x00\x00" # deferred c.b[2]
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with an embedded structure containing a varying array' do
    after :example do
      BinData::RegisteredClasses.unregister('test_struct')
    end

    let(:struct) do
      struct_with_array = Class.new(described_class) do
        default_parameters byte_align: 4
        endian :little

        ndr_uint16    :a
        ndr_var_array :b, type: :ndr_uint32
        ndr_uint16    :c
      end
      BinData::RegisteredClasses.register('test_struct', struct_with_array)
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint16  :a
        ndr_uint16  :b
        test_struct :c
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: 0, c: {a: 0, b: [], c: 0})
    end
    it 'reads itself' do
      values = {a: 44, b: 4444, c: {a: 5555, b: [1, 2, 3], c: 77}}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 5, b: 6, c: {a: 7, b: [1, 2, 3], c: 8})
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 5, b: 6, c: {a: 7, b: [1, 2, 3], c: 8})
      end
      it 'outputs the expected binary representation' do
        binary =  "\x05\x00"         # a
        binary << "\x06\x00"         # b
        binary << "\x07\x00"         # c.a
        binary << "\x00\x00"         # pad
        binary << "\x00\x00\x00\x00" # array offset
        binary << "\x03\x00\x00\x00" # array actual_count
        binary << "\x01\x00\x00\x00" # c.b[0]
        binary << "\x02\x00\x00\x00" # c.b[1]
        binary << "\x03\x00\x00\x00" # c.b[2]
        binary << "\x08\x00"         # c.c
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with an embedded structure containing a varying array of pointers' do
    after :example do
      BinData::RegisteredClasses.unregister('test_struct')
    end

    let(:struct) do
      struct_with_array = Class.new(described_class) do
        default_parameters byte_align: 4
        endian :little

        ndr_uint16    :a
        ndr_var_array :b, type: :ndr_uint32_ptr
        ndr_uint16    :c
      end
      BinData::RegisteredClasses.register('test_struct', struct_with_array)
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint16  :a
        ndr_uint16  :b
        test_struct :c
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: 0, c: {a: 0, b: [], c: 0})
    end
    it 'reads itself' do
      values = {a: 44, b: 4444, c: {a: 5555, b: [1, 2, 3], c: 77}}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 5, b: 6, c: {a: 7, b: [1, 2, 3], c: 8})
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 5, b: 6, c: {a: 7, b: [1, 2, 3], c: 8})
      end
      it 'outputs the expected binary representation' do
        binary =  "\x05\x00"         # a
        binary << "\x06\x00"         # b
        binary << "\x07\x00"         # c.a
        binary << "\x00\x00"         # pad
        binary << "\x00\x00\x00\x00" # array offset
        binary << "\x03\x00\x00\x00" # array actual_count
        binary << "\x01\x00\x00\x00" # c.b[0].ref_id
        binary << "\x02\x00\x00\x00" # c.b[1].ref_id
        binary << "\x03\x00\x00\x00" # c.b[2].ref_id
        binary << "\x08\x00"         # c.c
        binary << "\x00\x00"         # pad
        binary << "\x01\x00\x00\x00" # deferred c.b[0]
        binary << "\x02\x00\x00\x00" # deferred c.b[1]
        binary << "\x03\x00\x00\x00" # deferred c.b[2]
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with an embedded structure containing a conformant array' do
    after :example do
      BinData::RegisteredClasses.unregister('test_struct')
    end

    let(:struct) do
      struct_with_array = Class.new(described_class) do
        default_parameters byte_align: 4
        endian :little

        ndr_uint16     :a
        ndr_uint16     :b
        ndr_conf_array :c, type: :ndr_uint32
      end
      BinData::RegisteredClasses.register('test_struct', struct_with_array)
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint16  :a
        ndr_uint16  :b
        test_struct :c
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: 0, c: {a: 0, b: 0, c: []})
    end
    it 'reads itself' do
      values = {a: 44, b: 4444, c: {a: 5555, b: 77, c: [1, 2, 3]}}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 5, b: 6, c: {a: 7, b: 8, c: [1, 2, 3]})
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 5, b: 6, c: {a: 7, b:8, c: [1, 2, 3]})
      end
      it 'outputs the expected binary representation' do
        binary = "\x03\x00\x00\x00"  # array max_count
        binary << "\x05\x00"         # a
        binary << "\x06\x00"         # b
        binary << "\x07\x00"         # c.a
        binary << "\x08\x00"         # c.b
        binary << "\x01\x00\x00\x00" # c.c[0]
        binary << "\x02\x00\x00\x00" # c.c[1]
        binary << "\x03\x00\x00\x00" # c.c[2]
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with an embedded structure containing a conformant array of pointers' do
    after :example do
      BinData::RegisteredClasses.unregister('test_struct')
    end

    let(:struct) do
      struct_with_array = Class.new(described_class) do
        default_parameters byte_align: 4
        endian :little

        ndr_uint16     :a
        ndr_uint16     :b
        ndr_conf_array :c, type: :ndr_uint32_ptr
      end
      BinData::RegisteredClasses.register('test_struct', struct_with_array)
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint16  :a
        ndr_uint16  :b
        test_struct :c
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: 0, c: {a: 0, b: 0, c: []})
    end
    it 'reads itself' do
      values = {a: 44, b: 4444, c: {a: 5555, b: 77, c: [1, 2, 3]}}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 5, b: 6, c: {a: 7, b: 8, c: [1, 2, 3]})
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 5, b: 6, c: {a: 7, b:8, c: [1, 2, 3]})
      end
      it 'outputs the expected binary representation' do
        binary =  "\x03\x00\x00\x00" # array max_count
        binary << "\x05\x00"         # a
        binary << "\x06\x00"         # b
        binary << "\x07\x00"         # c.a
        binary << "\x08\x00"         # c.b
        binary << "\x01\x00\x00\x00" # c.b[0].ref_id
        binary << "\x02\x00\x00\x00" # c.b[1].ref_id
        binary << "\x03\x00\x00\x00" # c.b[2].ref_id
        binary << "\x01\x00\x00\x00" # deferred c.b[0]
        binary << "\x02\x00\x00\x00" # deferred c.b[1]
        binary << "\x03\x00\x00\x00" # deferred c.b[2]
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with an embedded structure containing a conformant varying array' do
    after :example do
      BinData::RegisteredClasses.unregister('test_struct')
    end

    let(:struct) do
      struct_with_array = Class.new(described_class) do
        default_parameters byte_align: 4
        endian :little

        ndr_uint16         :a
        ndr_uint16         :b
        ndr_conf_var_array :c, type: :ndr_uint32
      end
      BinData::RegisteredClasses.register('test_struct', struct_with_array)
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint16  :a
        ndr_uint16  :b
        test_struct :c
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: 0, c: {a: 0, b: 0, c: []})
    end
    it 'reads itself' do
      values = {a: 44, b: 4444, c: {a: 5555, b: 77, c: [1, 2, 3]}}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 5, b: 6, c: {a: 7, b: 8, c: [1, 2, 3]})
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 5, b: 6, c: {a: 7, b:8, c: [1, 2, 3]})
      end
      it 'outputs the expected binary representation' do
        binary =  "\x03\x00\x00\x00" # array max_count
        binary << "\x05\x00"         # a
        binary << "\x06\x00"         # b
        binary << "\x07\x00"         # c.a
        binary << "\x08\x00"         # c.b
        binary << "\x00\x00\x00\x00" # array offset
        binary << "\x03\x00\x00\x00" # array actual_count
        binary << "\x01\x00\x00\x00" # c.c[0]
        binary << "\x02\x00\x00\x00" # c.c[1]
        binary << "\x03\x00\x00\x00" # c.c[2]
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with an embedded structure containing a conformant varying array of pointers' do
    after :example do
      BinData::RegisteredClasses.unregister('test_struct')
    end

    let(:struct) do
      struct_with_array = Class.new(described_class) do
        default_parameters byte_align: 4
        endian :little

        ndr_uint16         :a
        ndr_uint16         :b
        ndr_conf_var_array :c, type: :ndr_uint32_ptr
      end
      BinData::RegisteredClasses.register('test_struct', struct_with_array)
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint16  :a
        ndr_uint16  :b
        test_struct :c
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: 0, c: {a: 0, b: 0, c: []})
    end
    it 'reads itself' do
      values = {a: 44, b: 4444, c: {a: 5555, b: 77, c: [1, 2, 3]}}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 5, b: 6, c: {a: 7, b: 8, c: [1, 2, 3]})
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 5, b: 6, c: {a: 7, b:8, c: [1, 2, 3]})
      end
      it 'outputs the expected binary representation' do
        binary =  "\x03\x00\x00\x00" # array max_count
        binary << "\x05\x00"         # a
        binary << "\x06\x00"         # b
        binary << "\x07\x00"         # c.a
        binary << "\x08\x00"         # c.b
        binary << "\x00\x00\x00\x00" # array offset
        binary << "\x03\x00\x00\x00" # array actual_count
        binary << "\x01\x00\x00\x00" # c.b[0].ref_id
        binary << "\x02\x00\x00\x00" # c.b[1].ref_id
        binary << "\x03\x00\x00\x00" # c.b[2].ref_id
        binary << "\x01\x00\x00\x00" # deferred c.b[0]
        binary << "\x02\x00\x00\x00" # deferred c.b[1]
        binary << "\x03\x00\x00\x00" # deferred c.b[2]
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with a pointer to a conformant arrays' do
    let(:struct) do
      struct_ptr = Class.new(RubySMB::Dcerpc::Ndr::NdrConfArray) do
        default_parameters(type: :ndr_uint32)
        extend RubySMB::Dcerpc::Ndr::PointerClassPlugin
      end
      BinData::RegisteredClasses.register('test_conf_array_ptr', struct_ptr)
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint32          :a
        ndr_uint32          :b
        test_conf_array_ptr :c
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: 0, c: :null)
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
        expect(subject).to eq(a: 4, b: 5, c: [1,2,3])
      end
      it 'outputs the expected binary representation' do
        binary =  "\x04\x00\x00\x00" # a
        binary << "\x05\x00\x00\x00" # b
        binary << "\x01\x00\x00\x00" # c.ref_id
        binary << "\x03\x00\x00\x00" # array max_count
        binary << "\x01\x00\x00\x00" # c[0]
        binary << "\x02\x00\x00\x00" # c[1]
        binary << "\x03\x00\x00\x00" # c[2]
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with a pointer to an embedded structure containing a conformant arrays' do
    after :example do
      BinData::RegisteredClasses.unregister('test_struct')
    end

    let(:struct) do
      struct_with_array = Class.new(described_class) do
        default_parameters byte_align: 4
        endian :little

        ndr_uint32         :a
        ndr_conf_var_array :b, type: :ndr_uint32
      end
      struct_ptr = Class.new(struct_with_array) do
        extend RubySMB::Dcerpc::Ndr::PointerClassPlugin
      end
      BinData::RegisteredClasses.register('test_struct_ptr', struct_ptr)
      Class.new(BinData::Record) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint32      :a
        ndr_uint32      :b
        test_struct_ptr :c
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: 0, c: :null)
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
        expect(subject).to eq(a: 5, b: 6, c: {a: 7, b: [1, 2, 3, 4]})
      end
      it 'outputs the expected binary representation' do
        binary =  "\x05\x00\x00\x00" # a
        binary << "\x06\x00\x00\x00" # b
        binary << "\x01\x00\x00\x00" # c.ref_id
        binary << "\x04\x00\x00\x00" # array max_count
        binary << "\x07\x00\x00\x00" # c.a
        binary << "\x00\x00\x00\x00" # array offset
        binary << "\x04\x00\x00\x00" # array actual_count
        binary << "\x01\x00\x00\x00" # c.b[0]
        binary << "\x02\x00\x00\x00" # c.b[1]
        binary << "\x03\x00\x00\x00" # c.b[2]
        binary << "\x04\x00\x00\x00" # c.b[3]
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with varying strings' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint8      :a
        ndr_var_string :b
        ndr_uint32     :c
        ndr_var_string :d
        ndr_boolean    :e
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: '', c: 0, d: '', e: false)
    end
    it 'reads itself' do
      values = {a: 44, b: 'Test1', c: 4444, d: 'Test22', e: true}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 1, b: 'Test1', c: 3, d: 'Test22', e: true)
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 1, b: 'Test1', c: 3, d: 'Test22', e: true)
      end
      it 'outputs the expected binary representation' do
        binary =  "\x01"             # a
        binary << "\x00\x00\x00"     # pad
        binary << "\x00\x00\x00\x00" # b offset
        binary << "\x05\x00\x00\x00" # b actual_count
        binary << 'Test1'            # b
        binary << "\x00\x00\x00"     # pad
        binary << "\x03\x00\x00\x00" # c
        binary << "\x00\x00\x00\x00" # b offset
        binary << "\x06\x00\x00\x00" # b actual_count
        binary << 'Test22'           # d
        binary << "\x00\x00"         # pad
        binary << "\x01\x00\x00\x00" # e
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with varying null terminated strings' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint8       :a
        ndr_var_stringz :b
        ndr_uint32      :c
        ndr_var_stringz :d
        ndr_boolean     :e
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: '', c: 0, d: '', e: false)
    end
    it 'reads itself' do
      values = {a: 44, b: 'Test1', c: 4444, d: 'Test22', e: true}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 1, b: 'Test1', c: 3, d: 'Test22', e: true)
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 1, b: 'Test1', c: 3, d: 'Test22', e: true)
      end
      it 'outputs the expected binary representation' do
        binary =  "\x01"             # a
        binary << "\x00\x00\x00"     # pad
        binary << "\x00\x00\x00\x00" # b offset
        binary << "\x06\x00\x00\x00" # b actual_count
        binary << "Test1\x00"        # b
        binary << "\x00\x00"         # pad
        binary << "\x03\x00\x00\x00" # c
        binary << "\x00\x00\x00\x00" # b offset
        binary << "\x07\x00\x00\x00" # b actual_count
        binary << "Test22\x00"       # d
        binary << "\x00"             # pad
        binary << "\x01\x00\x00\x00" # e
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with varying wide strings' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint8           :a
        ndr_var_wide_string :b
        ndr_uint32          :c
        ndr_var_wide_string :d
        ndr_boolean         :e
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: '', c: 0, d: '', e: false)
    end
    it 'reads itself' do
      values = {a: 44, b: 'Test1'.encode('utf-16le'), c: 4444, d: 'Test22'.encode('utf-16le'), e: true}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 1, b: 'Test1', c: 3, d: 'Test22', e: true)
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 1, b: 'Test1'.encode('utf-16le'), c: 3, d: 'Test22'.encode('utf-16le'), e: true)
      end
      it 'outputs the expected binary representation' do
        binary =  "\x01"                        # a
        binary << "\x00\x00\x00"                # pad
        binary << "\x00\x00\x00\x00"            # b offset
        binary << "\x05\x00\x00\x00"            # b actual_count
        binary << 'Test1'.encode('utf-16le').b  # b
        binary << "\x00\x00"                    # pad
        binary << "\x03\x00\x00\x00"            # c
        binary << "\x00\x00\x00\x00"            # b offset
        binary << "\x06\x00\x00\x00"            # b actual_count
        binary << 'Test22'.encode('utf-16le').b # d
        binary << "\x01\x00\x00\x00"            # e
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with varying null terminated wide strings' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint8            :a
        ndr_var_wide_stringz :b
        ndr_uint32           :c
        ndr_var_wide_stringz :d
        ndr_boolean          :e
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: '', c: 0, d: '', e: false)
    end
    it 'reads itself' do
      values = {a: 44, b: 'Test1'.encode('utf-16le'), c: 4444, d: 'Test22'.encode('utf-16le'), e: true}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 1, b: 'Test1', c: 3, d: 'Test22', e: true)
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 1, b: 'Test1'.encode('utf-16le'), c: 3, d: 'Test22'.encode('utf-16le'), e: true)
      end
      it 'outputs the expected binary representation' do
        binary =  "\x01"                            # a
        binary << "\x00\x00\x00"                    # pad
        binary << "\x00\x00\x00\x00"                # b offset
        binary << "\x06\x00\x00\x00"                # b actual_count
        binary << "Test1\x00".encode('utf-16le').b  # b
        binary << "\x03\x00\x00\x00"                # c
        binary << "\x00\x00\x00\x00"                # b offset
        binary << "\x07\x00\x00\x00"                # b actual_count
        binary << "Test22\x00".encode('utf-16le').b # d
        binary << "\x00\x00"                        # pad
        binary << "\x01\x00\x00\x00"                # e
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with conformant varying strings' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint8           :a
        ndr_uint32          :b
        ndr_boolean         :c
        ndr_conf_var_string :d
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: 0, c: false, d: '')
    end
    it 'reads itself' do
      values = {a: 44, b: 4444, c: true, d: 'Test22'}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 1, b: 3, c: true, d: 'Test22')
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 1, b: 3, c: true, d: 'Test22')
      end
      it 'outputs the expected binary representation' do
        binary =  "\x06\x00\x00\x00" # b max_count
        binary << "\x01"             # a
        binary << "\x00\x00\x00"     # pad
        binary << "\x03\x00\x00\x00" # b
        binary << "\x01\x00\x00\x00" # c
        binary << "\x00\x00\x00\x00" # b offset
        binary << "\x06\x00\x00\x00" # b actual_count
        binary << 'Test22'           # d
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with conformant varying null-terminated strings' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint8            :a
        ndr_uint32           :b
        ndr_boolean          :c
        ndr_conf_var_stringz :d
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: 0, c: false, d: '')
    end
    it 'reads itself' do
      values = {a: 44, b: 4444, c: true, d: 'Test22'}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 1, b: 3, c: true, d: 'Test22')
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 1, b: 3, c: true, d: 'Test22')
      end
      it 'outputs the expected binary representation' do
        binary =  "\x07\x00\x00\x00" # b max_count
        binary << "\x01"             # a
        binary << "\x00\x00\x00"     # pad
        binary << "\x03\x00\x00\x00" # b
        binary << "\x01\x00\x00\x00" # c
        binary << "\x00\x00\x00\x00" # b offset
        binary << "\x07\x00\x00\x00" # b actual_count
        binary << "Test22\x00"       # d
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with conformant varying wide strings' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint8                :a
        ndr_uint32               :b
        ndr_boolean              :c
        ndr_conf_var_wide_string :d
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: 0, c: false, d: '')
    end
    it 'reads itself' do
      values = {a: 44, b: 4444, c: true, d: 'Test22'.encode('utf-16le')}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 1, b: 3, c: true, d: 'Test22')
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 1, b: 3, c: true, d: 'Test22'.encode('utf-16le'))
      end
      it 'outputs the expected binary representation' do
        binary =  "\x06\x00\x00\x00"            # b max_count
        binary << "\x01"                        # a
        binary << "\x00\x00\x00"                # pad
        binary << "\x03\x00\x00\x00"            # b
        binary << "\x01\x00\x00\x00"            # c
        binary << "\x00\x00\x00\x00"            # b offset
        binary << "\x06\x00\x00\x00"            # b actual_count
        binary << 'Test22'.encode('utf-16le').b # d
        expect(subject.to_binary_s).to eq(binary.b)
      end
    end
  end

  context 'with conformant varying null-terminated wide strings' do
    let(:struct) do
      Class.new(described_class) do
        default_parameters byte_align: 4
        endian  :little

        ndr_uint8                 :a
        ndr_uint32                :b
        ndr_boolean               :c
        ndr_conf_var_wide_stringz :d
      end
    end

    it 'initializes the members to their default value' do
      expect(struct.new).to eq(a: 0, b: 0, c: false, d: '')
    end
    it 'reads itself' do
      values = {a: 44, b: 4444, c: true, d: 'Test22'.encode('utf-16le')}
      struct_instance = struct.new(values)
      expect(struct.read(struct_instance.to_binary_s)).to eq(values)
    end
    context 'with values' do
      subject do
        struct.new(a: 1, b: 3, c: true, d: 'Test22')
      end
      it 'returns the expected member values' do
        expect(subject).to eq(a: 1, b: 3, c: true, d: 'Test22'.encode('utf-16le'))
      end
      it 'outputs the expected binary representation' do
        binary =  "\x07\x00\x00\x00"                # b max_count
        binary << "\x01"                            # a
        binary << "\x00\x00\x00"                    # pad
        binary << "\x03\x00\x00\x00"                # b
        binary << "\x01\x00\x00\x00"                # c
        binary << "\x00\x00\x00\x00"                # b offset
        binary << "\x07\x00\x00\x00"                # b actual_count
        binary << "Test22\x00".encode('utf-16le').b # d
        expect(subject.to_binary_s).to eq(binary.b)
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
  NdrCharPtr: { parent_class: :NdrChar, data: 'C', binary: 'C', size: 1 },
  NdrBooleanPtr: { parent_class: :NdrBoolean, data: true, binary: [1].pack('L'), size: 4 },
  NdrStringPtr: {
    parent_class: :NdrConfVarString,
    data: 'Test1',
    binary: "#{[5].pack('L')}#{[0].pack('L')}#{[5].pack('L')}Test1", size: 4
  },
  NdrStringzPtr: {
    parent_class: :NdrConfVarStringz,
    data: 'Test2',
    binary: "#{[6].pack('L')}#{[0].pack('L')}#{[6].pack('L')}Test2\x00", size: 4
  },
  NdrWideStringPtr: {
    parent_class: :NdrConfVarWideString,
    data: 'Test3'.encode('utf-16le'),
    binary: "#{[5].pack('L')}#{[0].pack('L')}#{[5].pack('L')}#{'Test3'.encode('utf-16le').b}", size: 4
  },
  NdrWideStringzPtr: {
    parent_class: :NdrConfVarWideStringz,
    data: 'Test4'.encode('utf-16le'),
    binary: "#{[6].pack('L')}#{[0].pack('L')}#{[6].pack('L')}#{'Test4'.encode('utf-16le').b}\x00\x00", size: 4
  },
  NdrByteArrayPtr: {
    parent_class: :NdrConfVarArray,
    data: [1,2,3,4],
    binary: "#{[4].pack('L')}#{[0].pack('L')}#{[4].pack('L')}\x01\x02\x03\x04", size: 4
  },
  NdrFileTimePtr: {
    parent_class: :NdrFileTime,
    data: 132682503830000000,
    binary: [132682503830000000].pack('Q'), size: 4
  }
}.each do |ndr_class, info|
  RSpec.describe(RubySMB::Dcerpc::Ndr.const_get(ndr_class)) do
    subject { described_class.new }
    let(:class_with_ref_to) do
      struct = Class.new(BinData::Record) do
        endian :little
        ndr_uint32 :a
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
      it 'does not reset #ref_id to 0 when it has already been set to a value' do
        subject.ref_id = 5
        subject.initialize_instance
        expect(subject.ref_id).to eq(5)
      end
      it 'sets #ref_id to INITIAL_REF_ID by default when :initial_value parameter is provided' do
        test_instance = described_class.new(nil, {initial_value: info[:data]})
        expect(test_instance.ref_id).to eq(RubySMB::Dcerpc::Ndr::INITIAL_REF_ID)
      end
    end

    describe '#extend_top_level_class' do
      it 'extends to TopLevelPlugin' do
        expect(subject).to be_a(RubySMB::Dcerpc::Ndr::TopLevelPlugin)
      end
      it 'sets the pointer to top level pointer' do
        expect(subject.is_top_level_ptr).to be true
      end
      context 'when embedded in another structure' do
        let(:struct_class) do
          struct_class = Class.new(RubySMB::Dcerpc::Ndr::NdrStruct) do
            default_parameters byte_align: 4
            endian  :little
          end
          struct_class.send(described_class.bindata_name.to_sym, :c)
          struct_class
        end
        let(:top_level_class) do
          Class.new(BinData::Record) do
            endian  :little
            ndr_uint32  :a
            test_struct :b
          end
        end
        before :example do
          BinData::RegisteredClasses.register('test_struct', struct_class)
        end

        it 'extends the parents to TopLevelPlugin' do
          struct = top_level_class.new(a: 2, b: {c: info[:data]})
          expect(struct).to be_a(RubySMB::Dcerpc::Ndr::TopLevelPlugin)
          expect(struct.b).to be_a(RubySMB::Dcerpc::Ndr::TopLevelPlugin)
        end
        it 'only sets the top level structure as a top level pointer' do
          struct = top_level_class.new(a: 2, b: {c: info[:data]})
          expect(struct.is_top_level_ptr).to be true
          expect(struct.b.is_top_level_ptr).to be false
          expect(struct.b.c.is_top_level_ptr).to be false
        end
      end
    end

    describe '#snapshot' do
      it 'outputs :null by default' do
        expect(subject.snapshot).to eq(:null)
      end
      it 'outputs the referent when it refers to another Top-Level pointer' do
        expect(ref_to_instance.snapshot).to eq({a:1, b:info[:data], c:info[:data]})
      end
      # BinData does not support initial_value parameter for arrays
      unless ndr_class == :NdrByteArrayPtr
        it 'outputs the :initial_value parameter value when nothing has been assigned yet' do
          test_ptr = described_class.new(nil, {initial_value: info[:data]})
          expect(test_ptr.snapshot).to eq(info[:data])
        end
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
        expect(subject.new(info[:data]).to_binary_s).to eq("#{ref_id}#{info[:binary]}".b)
      end
      # BinData does not support initial_value parameter for arrays
      unless ndr_class == :NdrByteArrayPtr
        it 'outputs the :initial_value parameter value when nothing has been assigned yet' do
          test_ptr = described_class.new(nil, {initial_value: info[:data]})
          expect(test_ptr.new.to_binary_s).to eq("#{ref_id}#{info[:binary]}".b)
        end
      end
      context 'when embedded in another constructed structure'do
        let(:embedding_struct) do
          RubySMB::Dcerpc::Ndr::NdrConfArray.new([info[:data], info[:data]], type: described_class)
        end
        let(:output_str) do
          ref_id2 = [RubySMB::Dcerpc::Ndr::INITIAL_REF_ID + 1].pack('L')
          output_str = "#{[2].pack('L')}#{ref_id}#{ref_id2}".b
          align = (info[:size] - (output_str.size % info[:size])) % info[:size]
          output_str << "\x00".b * align
          output_str << info[:binary]
          align = (info[:size] - (output_str.size % info[:size])) % info[:size]
          output_str << "\x00".b * align
          output_str << info[:binary]
        end

        it 'does not change the embedded structure binary representation' do
          expect(embedding_struct[0].to_binary_s).to eq("#{ref_id}#{info[:binary]}".b)
          expect(embedding_struct[1].to_binary_s).to eq("#{ref_id}#{info[:binary]}".b)
        end
        it 'returns the correct aligned binary stream' do
          expect(embedding_struct.to_binary_s).to eq(output_str)
        end
        context 'when calling #to_binary_s on embedded structures' do
          # There was a bug where calling to_binary_s updated the ref_id
          # persistently, which resulted in wrong output
          it 'returns the correct aligned binary stream' do
            embedding_struct[0].to_binary_s
            embedding_struct[1].to_binary_s
            expect(embedding_struct.to_binary_s).to eq(output_str)
          end
        end
      end
    end

    describe '#do_read' do
      it 'reads a 32-bit zero binary representation as a null pointer' do
        expect(subject.read("\x00\x00\x00\x00".b)).to eq(:null)
      end
      it 'reads the referent ID followed by the representation of the referent' do
        expect(subject.read("#{ref_id}#{info[:binary]}")).to eq(info[:data])
        expect(subject.ref_id).to eq(RubySMB::Dcerpc::Ndr::INITIAL_REF_ID)
      end
      it 'reads the referent ID of the Top-Level pointer it is refering to' do
        align = (4 - (info[:binary].size % 4)) % 4
        pad = "\x00" * align
        binary_str = "#{[1].pack('L')}"\
                     "#{ref_id}"\
                     "#{info[:binary]}"\
                     "#{pad}"\
                     "#{ref_id}"
        test_instance = class_with_ref_to.read(binary_str)
        expect(test_instance.c.snapshot).to eq(info[:data])
        expect(test_instance.c.ref_id).to eq(test_instance.b.ref_id)
      end
      it 'reads the initial referent ID and the referent representaiton if it is not embedded in another constructed structure' do
        expect(subject.read("#{ref_id}#{info[:binary]}".b)).to eq(info[:data])
        expect(subject.ref_id).to eq(RubySMB::Dcerpc::Ndr::INITIAL_REF_ID)
      end
      context 'when embedded in another constructed structure'do
        let(:test_struct) { described_class.new(info[:data].dup) }
        let(:embedding_struct) do
          subject.assign(info[:data])
          RubySMB::Dcerpc::Ndr::NdrConfArray.new([subject, test_struct], type: described_class)
        end
        let(:binary_str) do
          ref_id2 = [RubySMB::Dcerpc::Ndr::INITIAL_REF_ID + 1].pack('L')
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
      context 'when the referent is in a NDR structure' do
        let(:class_with_ref_to) do
          test_struct_class = Class.new(RubySMB::Dcerpc::Ndr::NdrStruct) do
            default_parameters(byte_align: 4)
            ndr_uint32     :a
          end
          test_struct_class.send(described_class.bindata_name.to_sym, :ptr1)
          BinData::RegisteredClasses.register('test_struct', test_struct_class)
          struct = Class.new(BinData::Record) do
            test_struct :struct1
          end
          struct.send(described_class.bindata_name.to_sym, :ptr2, ref_to: :ptr1)
          struct
        end
        let(:ref_to_instance) { class_with_ref_to.new(struct1: { a: 2, ptr1: info[:data] }) }
        it 'returns the referent' do
          expect(ref_to_instance.ptr2.fetch_alias_referent).to eq(info[:data])
        end
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
  let(:ref_id) { RubySMB::Dcerpc::Ndr::INITIAL_REF_ID }
  let(:struct_with_ptr) do
    Class.new(RubySMB::Dcerpc::Ndr::NdrStruct) do
      default_parameters byte_align: 4
      endian :little

      ndr_uint32     :b
      ndr_char_ptr   :ptr2
      ndr_uint32_ptr :ptr3
    end
  end
  let(:random_struct) do
    Class.new(RubySMB::Dcerpc::Ndr::NdrStruct) do
      default_parameters byte_align: 4
      endian              :little

      ndr_uint32 :rand1
      ndr_uint32 :rand2
    end
  end

  before :example do
    BinData::RegisteredClasses.register('struct_with_ptr', struct_with_ptr)
    BinData::RegisteredClasses.register('random_struct', random_struct)
  end

  context 'with a BinData structure' do
    let(:test_struct) do
      Class.new(BinData::Record) do
        endian          :little

        ndr_uint32      :a
        ndr_char_ptr    :ptr1
        struct_with_ptr :d
        ndr_uint32_ptr  :ptr4
      end
    end
    let(:snapshot) { { a: 55, ptr1: 'M', d: { b: 66, ptr2: 'A', ptr3: 33 }, ptr4: 44 } }
    let(:binary) do
      "#{[55].pack('L')}"\
      "#{[ref_id].pack('L')}"\
      "M"\
      "\x00\x00\x00"\
      "#{[66].pack('L')}"\
      "#{[ref_id + 1].pack('L')}"\
      "#{[ref_id + 2].pack('L')}"\
      "A"\
      "\x00\x00\x00"\
      "#{[33].pack('L')}"\
      "#{[ref_id + 3].pack('L')}"\
      "#{[44].pack('L')}".b
    end
    subject { test_struct.new(snapshot) }

    it 'outputs the correct binary stream' do
      expect(subject.to_binary_s).to eq(binary)
    end
  end

  context 'with a BinData structure containing pointers with :initial_value set' do
    let(:test_struct) do
      Class.new(BinData::Record) do
        endian          :little

        ndr_uint32      :a
        ndr_char_ptr    :ptr1, initial_value: 'M'
        struct_with_ptr :d
        ndr_uint32_ptr  :ptr4, initial_value: 44
      end
    end
    let(:snapshot) { { a: 55, d: { b: 66, ptr2: 'A', ptr3: 33 } } }
    let(:binary) do
      "#{[55].pack('L')}"\
      "#{[ref_id].pack('L')}"\
      "M"\
      "\x00\x00\x00"\
      "#{[66].pack('L')}"\
      "#{[ref_id + 1].pack('L')}"\
      "#{[ref_id + 2].pack('L')}"\
      "A"\
      "\x00\x00\x00"\
      "#{[33].pack('L')}"\
      "#{[ref_id + 3].pack('L')}"\
      "#{[44].pack('L')}".b
    end
    subject { test_struct.new(snapshot) }

    it 'outputs the correct binary stream' do
      expect(subject.to_binary_s).to eq(binary)
    end
  end

  context 'with a BinData::Choice' do
    let(:test_struct) do
      Class.new(BinData::Record) do
        endian          :little

        ndr_uint32      :a
        ndr_char_ptr    :ptr1
        choice :choice1, selection: :a, byte_align: 4 do
          struct_with_ptr 55
        end
        ndr_uint32_ptr  :ptr4
      end
    end
    let(:snapshot) { { a: 55, ptr1: 'M', choice1: { b: 66, ptr2: 'A', ptr3: 33 }, ptr4: 44 } }
    let(:binary) do
      "#{[55].pack('L')}"\
      "#{[ref_id].pack('L')}"\
      "M"\
      "\x00\x00\x00"\
      "#{[66].pack('L')}"\
      "#{[ref_id + 1].pack('L')}"\
      "#{[ref_id + 2].pack('L')}"\
      "A"\
      "\x00\x00\x00"\
      "#{[33].pack('L')}"\
      "#{[ref_id + 3].pack('L')}"\
      "#{[44].pack('L')}".b
    end
    subject { test_struct.new(snapshot) }

    it 'outputs the correct binary stream' do
      expect(subject.to_binary_s).to eq(binary)
    end
  end

  context 'with a NDR array and an alias pointer' do
    let(:test_struct) do
      Class.new(BinData::Record) do
        endian          :little

        ndr_uint32      :a
        ndr_char_ptr    :ptr1
        ndr_conf_array  :array1, type: :random_struct
        struct_with_ptr :d
        ndr_uint32_ptr  :ptr4, ref_to: :ptr3
      end
    end
    let(:snapshot) do
      {
        a: 0xF1,
        ptr1: 'A',
        array1: [
          { rand1: 0xF2, rand2: 0xF3 },
          { rand1: 0xF4, rand2: 0xF5 }
        ],
        d: { b: 0xF6, ptr2: 'B', ptr3: 0xF7 }
      }
    end
    let(:binary) do
      "#{[0xF1].pack('L<')}"\
      "#{[ref_id].pack('L<')}"\
      "A"\
      "\x00\x00\x00"\
      "#{[2].pack('L<')}"\
      "#{[0xF2].pack('L<')}"\
      "#{[0xF3].pack('L<')}"\
      "#{[0xF4].pack('L<')}"\
      "#{[0xF5].pack('L<')}"\
      "#{[0xF6].pack('L<')}"\
      "#{[ref_id + 1].pack('L<')}"\
      "#{[ref_id + 2].pack('L<')}"\
      "B"\
      "\x00\x00\x00"\
      "#{[0xF7].pack('L<')}"\
      "#{[ref_id + 2].pack('L<')}"
    end
    subject { test_struct.new(snapshot) }

    it 'outputs the correct binary stream' do
      expect(subject.to_binary_s).to eq(binary)
    end

    context 'when the alias pointer is positioned after the referent pointer' do
      let(:test_struct2) do
        Class.new(BinData::Record) do
          endian          :little

          ndr_uint32      :a
          ndr_char_ptr    :ptr1
          ndr_conf_array  :array1, type: :random_struct
          # :ptr3 is part of :d structure, which appears after :ptr4
          ndr_uint32_ptr  :ptr4, ref_to: :ptr3
          struct_with_ptr :d
        end
      end

      context 'with #snapshot' do
        it 'raises an exception' do
          expect { test_struct2.new(snapshot).snapshot }.to raise_error(ArgumentError)
        end
      end

      context 'with #to_binary_s' do
        it 'raises an exception' do
          expect { test_struct2.new(snapshot).to_binary_s }.to raise_error(ArgumentError)
        end
      end
    end

    context 'when the alias pointer refers to a non-existing pointer' do
      let(:test_struct2) do
        Class.new(BinData::Record) do
          endian          :little

          ndr_uint32      :a
          ndr_char_ptr    :ptr1
          ndr_conf_array  :array1, type: :random_struct
          ndr_uint32_ptr  :ptr4, ref_to: :ptr5
          struct_with_ptr :d
        end
      end

      it 'raises an exception' do
        expect { test_struct2.new(snapshot).snapshot }.to raise_error(ArgumentError)
      end
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

    describe RubySMB::Dcerpc::Ndr::NdrBoolean do
      it_behaves_like(
        'an aligned structure',
        field_value: true,
        field_binary: [1].pack('L')
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrWideChar do
      it_behaves_like(
        'an aligned structure',
        align: 2,
        field_value: 'B'.encode('utf-16le'),
        field_binary: "B\x00"
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrEnum do
      it_behaves_like(
        'an aligned structure',
        align: 2,
        field_value: 3,
        field_binary: [3].pack('S')
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrFixArray do
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

    describe RubySMB::Dcerpc::Ndr::NdrConfArray do
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
          align: 8,
          field_value: [1, 2],
          field_binary: [2].pack('L') + [0].pack('L') + [1, 2].pack('QQ')
        ) do
          let(:params) { {type: :ndr_uint64 } }
        end
      end
    end

    describe RubySMB::Dcerpc::Ndr::NdrVarArray do
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
          align: 8,
          field_value: [1, 2],
          field_binary: [0].pack('L') + [2].pack('L') + [1, 2].pack('QQ')
        ) do
          let(:params) { {type: :ndr_uint64 } }
        end
      end
    end

    describe RubySMB::Dcerpc::Ndr::NdrConfVarArray do
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
          align: 8,
          field_value: [1, 2],
          field_binary: [2].pack('L') + [0].pack('L') + [2].pack('L') + [0].pack('L') + [1, 2].pack('QQ')
        ) do
          let(:params) { {type: :ndr_uint64 } }
        end
      end
    end

    describe RubySMB::Dcerpc::Ndr::NdrVarString do
      it_behaves_like(
        'an aligned structure',
        field_value: "Test1",
        field_binary: [0].pack('L') + [5].pack('L') + "Test1"
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrVarStringz do
      it_behaves_like(
        'an aligned structure',
        field_value: "Test1",
        field_binary: [0].pack('L') + [6].pack('L') + "Test1\x00"
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrVarWideString do
      it_behaves_like(
        'an aligned structure',
        field_value: "Test1".encode('utf-16le'),
        field_binary: [0].pack('L') + [5].pack('L') + "Test1".encode('utf-16le').force_encoding('ASCII')
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrVarWideStringz do
      it_behaves_like(
        'an aligned structure',
        field_value: "Test1".encode('utf-16le'),
        field_binary: [0].pack('L') + [6].pack('L') + "Test1\x00".encode('utf-16le').force_encoding('ASCII')
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrConfVarString do
      it_behaves_like(
        'an aligned structure',
        field_value: "Test1",
        field_binary: [5].pack('L') + [0].pack('L') + [5].pack('L') + "Test1"
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrConfVarStringz do
      it_behaves_like(
        'an aligned structure',
        field_value: "Test1",
        field_binary: [6].pack('L') + [0].pack('L') + [6].pack('L') + "Test1\x00"
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrConfVarWideString do
      it_behaves_like(
        'an aligned structure',
        field_value: "Test1".encode('utf-16le'),
        field_binary: [5].pack('L') + [0].pack('L') + [5].pack('L') + "Test1".encode('utf-16le').force_encoding('ASCII')
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrConfVarWideStringz do
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
      NdrCharPtr: { data: 'C', binary: 'C' },
      NdrBooleanPtr: { data: true, binary: [1].pack('L')},
      NdrStringPtr: { data: 'Test1', binary: "#{[5].pack('L')}#{[0].pack('L')}#{[5].pack('L')}Test1" },
      NdrStringzPtr: { data: 'Test2', binary: "#{[6].pack('L')}#{[0].pack('L')}#{[6].pack('L')}Test2\x00" },
      NdrWideStringPtr: { data: 'Test3'.encode('utf-16le'), binary: "#{[5].pack('L')}#{[0].pack('L')}#{[5].pack('L')}#{'Test3'.encode('utf-16le').force_encoding('ASCII')}" },
      NdrWideStringzPtr: { data: 'Test4'.encode('utf-16le'), binary: "#{[6].pack('L')}#{[0].pack('L')}#{[6].pack('L')}#{'Test4'.encode('utf-16le').force_encoding('ASCII')}\x00\x00" },
      NdrByteArrayPtr: { data: [1,2,3,4], binary: "#{[4].pack('L')}#{[0].pack('L')}#{[4].pack('L')}\x01\x02\x03\x04" },
      NdrFileTimePtr: { data: 132682503830000000, binary: [132682503830000000].pack('Q') }
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
        # :byte_align is set according to the type of the largest element in
        # the structure (uint32):
        let(:params) { {byte_align: 4 } }
      end
    end
  end

  context 'in a conformant array' do
    let(:params) { {} }
    before :example do
      struct_class.send(:ndr_conf_array, :aligned_field, { :type => [ described_class, params ] } )
    end

    describe RubySMB::Dcerpc::Ndr::NdrBoolean do
      it_behaves_like(
        'an aligned structure',
        field_value: [true, false, true],
        field_binary: [3].pack('L') + [1, 0, 1].pack('LLL')
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrWideChar do
      it_behaves_like(
        'an aligned structure',
        field_value: 'ABC'.encode('utf-16le').chars,
        field_binary: [3].pack('L') + "A\x00B\x00C\x00"
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrEnum do
      it_behaves_like(
        'an aligned structure',
        field_value: [1, 2, 3],
        field_binary: [3].pack('L') + [1, 2, 3].pack('SSS')
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrFixArray do
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
          align: 8,
          field_value: [ [1, 2], [3, 4] ],
          field_binary: [2].pack('L') + [0].pack('L') + [1, 2].pack('QQ') + [3, 4].pack('QQ')
        ) do
          let(:params) { {type: :ndr_uint64, initial_length: 2, byte_align: 8} }
        end
      end
    end

    describe RubySMB::Dcerpc::Ndr::NdrConfArray do
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
          align: 8,
          field_value: [ [1, 2], [3, 4] ],
          field_binary: [2].pack('L') + [0].pack('L') + [2].pack('L') + [0].pack('L') + [1, 2].pack('QQ') + [2].pack('L') + [0].pack('L') + [3, 4].pack('QQ')
        ) do
          let(:params) { {type: :ndr_uint64} }
        end
      end
    end

    describe RubySMB::Dcerpc::Ndr::NdrVarArray do
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
          align: 8,
          field_value: [ [1, 2], [3, 4] ],
          field_binary: [2].pack('L') + [0].pack('L') + [0].pack('L') + [2].pack('L') + [1, 2].pack('QQ') + [0].pack('L') + [2].pack('L') + [3, 4].pack('QQ')
        ) do
          let(:params) { {type: :ndr_uint64} }
        end
      end
    end

    describe RubySMB::Dcerpc::Ndr::NdrConfVarArray do
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
          align: 8,
          field_value: [ [1, 2], [3, 4] ],
          field_binary: [2].pack('L') + [0].pack('L') + [2].pack('L') + [0].pack('L') + [2].pack('L') + [0].pack('L') + [1, 2].pack('QQ') + [2].pack('L') + [0].pack('L') + [2].pack('L') + [0].pack('L') + [3, 4].pack('QQ')
        ) do
          let(:params) { {type: :ndr_uint64} }
        end
      end
    end

    describe RubySMB::Dcerpc::Ndr::NdrVarString do
      it_behaves_like(
        'an aligned structure',
        field_value: [ "Test1", "Test2" ],
        field_binary: [2].pack('L') + [0].pack('L') + [5].pack('L') + "Test1" + [0].pack('L') + [5].pack('L') + "Test2"
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrVarStringz do
      it_behaves_like(
        'an aligned structure',
        field_value: [ "Test1", "Test2" ],
        field_binary: [2].pack('L') + [0].pack('L') + [6].pack('L') + "Test1\x00" + [0].pack('L') + [6].pack('L') + "Test2\x00"
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrVarWideString do
      it_behaves_like(
        'an aligned structure',
        field_value: [ "Test1".encode('utf-16le'), "Test2".encode('utf-16le') ],
        field_binary: [2].pack('L') + [0].pack('L') + [5].pack('L') + "Test1".encode('utf-16le').force_encoding('ASCII') + [0].pack('L') + [5].pack('L') + "Test2".encode('utf-16le').force_encoding('ASCII')
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrVarWideStringz do
      it_behaves_like(
        'an aligned structure',
        field_value: [ "Test1".encode('utf-16le'), "Test2".encode('utf-16le') ],
        field_binary: [2].pack('L') + [0].pack('L') + [6].pack('L') + "Test1\x00".encode('utf-16le').force_encoding('ASCII') + [0].pack('L') + [6].pack('L') + "Test2\x00".encode('utf-16le').force_encoding('ASCII')
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrConfVarString do
      it_behaves_like(
        'an aligned structure',
        field_value: [ "Test1", "Test2" ],
        field_binary: [2].pack('L') + [5].pack('L') + [0].pack('L') + [5].pack('L') + "Test1" + [5].pack('L') + [0].pack('L') + [5].pack('L') + "Test2"
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrConfVarStringz do
      it_behaves_like(
        'an aligned structure',
        field_value: [ "Test1", "Test2" ],
        field_binary: [2].pack('L') + [6].pack('L') + [0].pack('L') + [6].pack('L') + "Test1\x00" + [6].pack('L') + [0].pack('L') + [6].pack('L') + "Test2\x00"
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrConfVarWideString do
      it_behaves_like(
        'an aligned structure',
        field_value: [ "Test1".encode('utf-16le'), "Test2".encode('utf-16le') ],
        field_binary: [2].pack('L') + [5].pack('L') + [0].pack('L') + [5].pack('L') + "Test1".encode('utf-16le').force_encoding('ASCII') + [5].pack('L') + [0].pack('L') + [5].pack('L') + "Test2".encode('utf-16le').force_encoding('ASCII')
      )
    end

    describe RubySMB::Dcerpc::Ndr::NdrConfVarWideStringz do
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
      NdrCharPtr: { data: 'C', binary: 'C', size: 1 },
      NdrBooleanPtr: { data: true, binary: [1].pack('L'), size: 4 },
      NdrStringPtr: {
        data: 'Test1',
        binary: "#{[5].pack('L')}#{[0].pack('L')}#{[5].pack('L')}Test1",
        size: 4
      },
      NdrStringzPtr: {
        data: 'Test2',
        binary: "#{[6].pack('L')}#{[0].pack('L')}#{[6].pack('L')}Test2\x00",
        size: 4
      },
      NdrWideStringPtr: {
        data: 'Test3'.encode('utf-16le'),
        binary: "#{[5].pack('L')}#{[0].pack('L')}#{[5].pack('L')}#{'Test3'.encode('utf-16le').b}",
        size: 4
      },
      NdrWideStringzPtr: {
        data: 'Test4'.encode('utf-16le'),
        binary: "#{[6].pack('L')}#{[0].pack('L')}#{[6].pack('L')}#{'Test4'.encode('utf-16le').b}\x00\x00",
        size: 4
      },
      NdrByteArrayPtr: {
        data: [1,2,3,4],
        binary: "#{[4].pack('L')}#{[0].pack('L')}#{[4].pack('L')}\x01\x02\x03\x04",
        size: 4
      },
      NdrFileTimePtr: { data: 132682503830000000, binary: [132682503830000000].pack('Q'), size: 4 }
    }.each do |ndr_class, info|
      describe(RubySMB::Dcerpc::Ndr.const_get(ndr_class)) do
        ref_id = [RubySMB::Dcerpc::Ndr::INITIAL_REF_ID].pack('L')
        ref_id2 = [RubySMB::Dcerpc::Ndr::INITIAL_REF_ID + 1].pack('L')
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

RSpec.describe RubySMB::Dcerpc::Ndr::TypeSerialization1CommonTypeHeader do
  it 'is a BinData::NdrStruct class' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
  end
  it 'has :byte_align parameter set to the expected value' do
    expect(described_class.default_parameters[:byte_align]).to eq(8)
  end

  subject { described_class.new }

  it { is_expected.to respond_to :version }
  it { is_expected.to respond_to :endianness }
  it { is_expected.to respond_to :common_header_length }
  it { is_expected.to respond_to :filler }

  context 'with #version' do
    it 'is a NdrUint8' do
      expect(subject.version).to be_a RubySMB::Dcerpc::Ndr::NdrUint8
    end
    it 'returns 1 by default' do
      expect(subject.version).to eq(1)
    end
  end

  context 'with #endianness' do
    it 'is a NdrUint8' do
      expect(subject.endianness).to be_a RubySMB::Dcerpc::Ndr::NdrUint8
    end
    it 'returns 0x10 by default' do
      expect(subject.endianness).to eq(0x10)
    end
  end

  context 'with #common_header_length' do
    it 'is a NdrUint16' do
      expect(subject.common_header_length).to be_a RubySMB::Dcerpc::Ndr::NdrUint16
    end
    it 'returns 8 by default' do
      expect(subject.common_header_length).to eq(8)
    end
  end

  context 'with #filler' do
    it 'is a NdrUint32' do
      expect(subject.filler).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
    it 'returns 0xCCCCCCCC by default' do
      expect(subject.filler).to eq(0xCCCCCCCC)
    end
  end

  it 'reads itself' do
    values = {version: 4, endianness: 0x33, common_header_length: 44, filler: 0xFFFFFFFF}
    struct_instance = described_class.new(values)
    expect(described_class.read(struct_instance.to_binary_s)).to eq(values)
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::TypeSerialization1PrivateHeader do
  it 'is a BinData::NdrStruct class' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
  end
  it 'has :byte_align parameter set to the expected value' do
    expect(described_class.default_parameters[:byte_align]).to eq(8)
  end

  subject { described_class.new }

  it { is_expected.to respond_to :object_buffer_length }
  it { is_expected.to respond_to :filler }

  context 'with #object_buffer_length' do
    it 'is a NdrUint32' do
      expect(subject.object_buffer_length).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  context 'with #filler' do
    it 'is a NdrUint32' do
      expect(subject.filler).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
    it 'returns 0x00000000 by default' do
      expect(subject.filler).to eq(0x00000000)
    end
  end

  it 'reads itself' do
    values = {object_buffer_length: 4, filler: 0xFFFFFFFF}
    struct_instance = described_class.new(values)
    expect(described_class.read(struct_instance.to_binary_s)).to eq(values)
  end
end

RSpec.describe RubySMB::Dcerpc::Ndr::TypeSerialization1 do
  it 'is a BinData::NdrStruct class' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
  end
  it 'has :byte_align parameter set to the expected value' do
    expect(described_class.default_parameters[:byte_align]).to eq(8)
  end

  subject { described_class.new }

  it { is_expected.to respond_to :common_header }
  it { is_expected.to respond_to :private_header }

  context 'with #common_header' do
    it 'is a TypeSerialization1CommonTypeHeader structure' do
      expect(subject.common_header).to be_a RubySMB::Dcerpc::Ndr::TypeSerialization1CommonTypeHeader
    end
  end

  context 'with #private_header' do
    it 'is a TypeSerialization1PrivateHeader structure' do
      expect(subject.private_header).to be_a RubySMB::Dcerpc::Ndr::TypeSerialization1PrivateHeader
    end
  end

  it 'reads itself' do
    values = {
      common_header: {version: 4, endianness: 0x33, common_header_length: 44, filler: 0xFFFFFFFF},
      private_header: {object_buffer_length: 4, filler: 0xFFFFFFFF}
    }
    struct_instance = described_class.new(values)
    expect(described_class.read(struct_instance.to_binary_s)).to eq(values)
  end
end
