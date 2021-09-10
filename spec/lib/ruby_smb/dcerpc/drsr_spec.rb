require 'ruby_smb/dcerpc/client'

RSpec.describe RubySMB::Dcerpc::Drsr do
  def random_str(nb = 8)
    nb.times.map { rand('a'.ord..'z'.ord).chr }.join
  end

  let(:drsr) do
    RubySMB::Dcerpc::Client.new('1.2.3.4', RubySMB::Dcerpc::Drsr)
  end

  describe described_class::DrsHandle do
    subject(:packet) { described_class.new }

    it 'is a Ndr::NdrContextHandle' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrContextHandle
    end
    it 'reads itself' do
      value = {
        context_handle_attributes: rand(0xFFFFFFFF),
        context_handle_uuid: 'ee1ecfe6-109d-11ec-82a8-0242ac130003'
      }
      new_struct = described_class.new
      new_struct.set(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::DrsConfStringz16 do
    subject(:packet) { described_class.new }

    it 'is a Ndr::NdrConfArray' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrConfArray
    end
    it 'has elements of type RubySMB::Dcerpc::Ndr::NdrWideChar' do
      expect(packet[0]).to be_a RubySMB::Dcerpc::Ndr::NdrWideChar
    end
    it 'reads itself' do
      value = 'Test String'.encode('utf-16le').chars
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::DsName  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :struct_len }
    it { is_expected.to respond_to :sid_len }
    it { is_expected.to respond_to :guid }
    it { is_expected.to respond_to :sid }
    it { is_expected.to respond_to :name_len }
    it { is_expected.to respond_to :string_name }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is little endian' do
      expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
    end
    describe '#struct_len' do
      it 'is a NdrUint32 structure' do
        expect(packet.struct_len).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
      it 'defaults to the size of the structure' do
        expect(packet.struct_len).to eq(packet.num_bytes)
      end
    end
    describe '#sid_len' do
      it 'is a NdrUint32 structure' do
        expect(packet.sid_len).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#guid' do
      it 'is a Uuid structure' do
        expect(packet.guid).to be_a RubySMB::Dcerpc::Uuid
      end
    end
    describe '#sid' do
      it 'is a String' do
        expect(packet.sid).to be_a BinData::String
      end
      it 'is always 28 bytes long' do
        expect(packet.sid.size).to eq(28)
        packet.sid = 'AAA'
        expect(packet.sid.size).to eq(28)
      end
    end
    describe '#name_len' do
      it 'is a NdrUint32 structure' do
        expect(packet.name_len).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
      it 'is the length of #string_name without the null terminator' do
        packet.string_name = "Test123\x00".encode('utf-16le').chars
        expect(packet.name_len).to eq('Test123'.size)
      end
    end
    describe '#string_name' do
      it 'is a DrsConfStringz16 structure' do
        expect(packet.string_name).to be_a RubySMB::Dcerpc::Drsr::DrsConfStringz16
      end
    end
    it 'reads itself' do
      value = {
        struct_len: 30,
        sid_len: 4,
        guid: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
        sid: 'A' * 28,
        string_name: 'Test string'.encode('utf-16le').chars
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value.merge(name_len: value[:string_name].size - 1))
    end
  end

  describe described_class::DsNamePtr  do
    subject(:packet) { described_class.new }

    it 'is a DsName' do
      expect(described_class).to be < RubySMB::Dcerpc::Drsr::DsName
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'has a referent which is 4-bytes aligned' do
      expect(packet.eval_parameter(:referent_byte_align)).to eq(4)
    end
    it 'reads itself' do
      value = {
        struct_len: rand(0xFFFFFFFF),
        sid_len: rand(0xFFFFFFFF),
        guid: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
        sid: 'A' * 28,
        string_name: 'Test string'.encode('utf-16le').chars
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value.merge(name_len: value[:string_name].size - 1))
    end
  end

  describe described_class::Usn do
    subject(:packet) { described_class.new }

    it 'is a BinData::Int64le' do
      expect(described_class).to be < BinData::Int64le
    end
    it 'is 8-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(8)
    end
    it 'reads itself' do
      value = rand(0xFFFFFFFF)
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::UsnVector  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :usn_high_obj_update }
    it { is_expected.to respond_to :usn_reserved }
    it { is_expected.to respond_to :usn_high_prop_update }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 8-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(8)
    end
    describe '#usn_high_obj_update' do
      it 'is a Usn structure' do
        expect(packet.usn_high_obj_update).to be_a RubySMB::Dcerpc::Drsr::Usn
      end
    end
    describe '#usn_reserved' do
      it 'is a Usn structure' do
        expect(packet.usn_reserved).to be_a RubySMB::Dcerpc::Drsr::Usn
      end
    end
    describe '#usn_high_prop_update' do
      it 'is a Usn structure' do
        expect(packet.usn_high_prop_update).to be_a RubySMB::Dcerpc::Drsr::Usn
      end
    end
    it 'reads itself' do
      value = {
        usn_high_obj_update: rand(0xFFFFFFFF),
        usn_reserved: rand(0xFFFFFFFF),
        usn_high_prop_update:rand(0xFFFFFFFF)
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::UptodateCursorV1  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :uuid_dsa }
    it { is_expected.to respond_to :usn_high_prop_update }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 8-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(8)
    end
    describe '#uuid_dsa' do
      it 'is a Uuid structure' do
        expect(packet.uuid_dsa).to be_a RubySMB::Dcerpc::Uuid
      end
    end
    describe '#usn_high_prop_update' do
      it 'is a Usn structure' do
        expect(packet.usn_high_prop_update).to be_a RubySMB::Dcerpc::Drsr::Usn
      end
    end
    it 'reads itself' do
      value = {
        uuid_dsa:'ee1ecfe6-109d-11ec-82a8-0242ac130003',
        usn_high_prop_update: rand(0xFFFFFFFF)
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::UptodateVectorV1Ext  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :dw_version }
    it { is_expected.to respond_to :dw_reserved1 }
    it { is_expected.to respond_to :c_num_cursors }
    it { is_expected.to respond_to :dw_reserved2 }
    it { is_expected.to respond_to :rg_cursors }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 8-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(8)
    end
    describe '#dw_version' do
      it 'is a NdrUint32 structure' do
        expect(packet.dw_version).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#dw_reserved1' do
      it 'is a NdrUint32 structure' do
        expect(packet.dw_reserved1).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#c_num_cursors' do
      it 'is a NdrUint32 structure' do
        expect(packet.c_num_cursors).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#dw_reserved2' do
      it 'is a NdrUint32 structure' do
        expect(packet.dw_reserved2).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#rg_cursors' do
      it 'is a NdrConfArray structure' do
        expect(packet.rg_cursors).to be_a RubySMB::Dcerpc::Ndr::NdrConfArray
      end
      it 'has elements of type UptodateCursorV1' do
        expect(packet.rg_cursors[0]).to be_a RubySMB::Dcerpc::Drsr::UptodateCursorV1
      end
    end
    it 'reads itself' do
      value = {
        dw_version: rand(0xFFFFFFFF),
        dw_reserved1: rand(0xFFFFFFFF),
        c_num_cursors: rand(0xFFFFFFFF),
        dw_reserved2: rand(0xFFFFFFFF),
        rg_cursors: [{
          uuid_dsa:'ee1ecfe6-109d-11ec-82a8-0242ac130003',
          usn_high_prop_update: rand(0xFFFFFFFF)
        }]
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::UptodateVectorV1ExtPtr  do
    subject(:packet) { described_class.new }

    it 'is a UptodateVectorV1Ext' do
      expect(described_class).to be < RubySMB::Dcerpc::Drsr::UptodateVectorV1Ext
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'has a referent which is 8-bytes aligned' do
      expect(packet.eval_parameter(:referent_byte_align)).to eq(8)
    end
    it 'reads itself' do
      value = {
        dw_version: rand(0xFFFFFFFF),
        dw_reserved1: rand(0xFFFFFFFF),
        c_num_cursors: rand(0xFFFFFFFF),
        dw_reserved2: rand(0xFFFFFFFF),
        rg_cursors: [{
          uuid_dsa:'ee1ecfe6-109d-11ec-82a8-0242ac130003',
          usn_high_prop_update: rand(0xFFFFFFFF)
        }]
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::AttrtypRequestPlugin  do
    let(:test_struct) do
      Class.new(BinData::Record) do
        include RubySMB::Dcerpc::Drsr::AttrtypRequestPlugin
        partial_attr_vector_v1_ext_ptr :p_partial_attr_set
        schema_prefix_table            :prefix_table_dest
      end.new
    end

    describe '#add_attrtyp_from_oid' do
      it 'correctly adds ATTRYP from OID' do
        oid = '1.2.840.113556.1.2.1'
        expected_struct = {
          p_partial_attr_set: {
            dw_version: 1,
            dw_reserved1: 0,
            c_attrs: 1,
            rg_partial_attr: [1]
          },
          prefix_table_dest: {
            prefix_count: 1,
            p_prefix_entry: [{ ndx: 0, prefix: {oid_length: 8, elements: [42, 134, 72, 134, 247, 20, 1, 2]}}]
          }
        }
        test_struct.add_attrtyp_from_oid(oid)
        expect(test_struct).to eq(expected_struct)
      end
    end
  end

  describe described_class::AttrtypResponsePlugin  do
    let(:test_struct) do
      values = {
        prefix_table_src: {
          p_prefix_entry: [
            { ndx: 1, prefix: {elements: [96, 134, 72, 1, 101, 2, 1, 4]}},
            { ndx: 2, prefix: {elements: [42, 134, 72, 134, 247, 20, 1, 2]}}
          ]
        }
      }
      Class.new(BinData::Record) do
        include RubySMB::Dcerpc::Drsr::AttrtypResponsePlugin
        schema_prefix_table :prefix_table_src
      end.new(values)
    end

    describe '#oid_from_attid' do
      it 'correctly converts ATTRYP to OID' do
        attr_typ = 131073
        oid = '1.2.840.113556.1.2.1'
        expect(test_struct.oid_from_attid(attr_typ)).to eq(oid)
      end
    end
  end

  describe described_class::Attrtyp do
    it 'is a Ndr::NdrUint32' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe described_class::PartialAttrVectorV1Ext  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :dw_version }
    it { is_expected.to respond_to :dw_reserved1 }
    it { is_expected.to respond_to :c_attrs }
    it { is_expected.to respond_to :rg_partial_attr }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    describe '#dw_version' do
      it 'is a NdrUint32 structure' do
        expect(packet.dw_version).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
      it 'defaults to 1' do
        expect(packet.dw_version).to eq(1)
      end
    end
    describe '#dw_reserved1' do
      it 'is a NdrUint32 structure' do
        expect(packet.dw_reserved1).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#c_attrs' do
      it 'is a NdrUint32 structure' do
        expect(packet.c_attrs).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
      it 'defaults to #rg_partial_attr max_count value' do
        packet.rg_partial_attr = [1,2,3]
        expect(packet.c_attrs).to eq(3)
      end
    end
    describe '#rg_partial_attr' do
      it 'is a Ndr::NdrConfArray' do
        expect(packet.rg_partial_attr).to be_a RubySMB::Dcerpc::Ndr::NdrConfArray
      end
      it 'has elements of type Attrtyp' do
        expect(packet.rg_partial_attr[0]).to be_a RubySMB::Dcerpc::Drsr::Attrtyp
      end
    end
    it 'reads itself' do
      value = {
        dw_version: rand(0xFFFFFFFF),
        dw_reserved1: rand(0xFFFFFFFF),
        c_attrs: 3,
        rg_partial_attr: [rand(0xFFFFFFFF), rand(0xFFFFFFFF), rand(0xFFFFFFFF)]
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::PartialAttrVectorV1ExtPtr  do
    subject(:packet) { described_class.new }

    it 'is a PartialAttrVectorV1Ext' do
      expect(described_class).to be < RubySMB::Dcerpc::Drsr::PartialAttrVectorV1Ext
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'has a referent which is 4-bytes aligned' do
      expect(packet.eval_parameter(:referent_byte_align)).to eq(4)
    end
    it 'reads itself' do
      value = {
        dw_version: rand(0xFFFFFFFF),
        dw_reserved1: rand(0xFFFFFFFF),
        c_attrs: 3,
        rg_partial_attr: [rand(0xFFFFFFFF), rand(0xFFFFFFFF), rand(0xFFFFFFFF)]
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::DrsByteArrayPtr  do
    subject(:packet) { described_class.new }

    it 'is a Ndr::NdrConfArray' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrConfArray
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'has elements of type Ndr::NdrUint8' do
      expect(packet[0]).to be_a RubySMB::Dcerpc::Ndr::NdrUint8
    end
    it 'reads itself' do
      value = [rand(0xFF), rand(0xFF), rand(0xFF)]
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::OidT  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :oid_length }
    it { is_expected.to respond_to :elements }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    describe '#oid_length' do
      it 'is a NdrUint32 structure' do
        expect(packet.oid_length).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
      it 'defaults to the size of #drs_byte_array_ptr' do
        packet.elements = [1,2,3,4]
        expect(packet.oid_length).to eq(4)
      end
    end
    describe '#elements' do
      it 'is a DrsByteArrayPtr' do
        expect(packet.elements).to be_a RubySMB::Dcerpc::Drsr::DrsByteArrayPtr
      end
    end
    it 'reads itself' do
      value = {
        oid_length: 3,
        elements: [rand(0xFF), rand(0xFF), rand(0xFF)]
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::PrefixTableEntry  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :ndx }
    it { is_expected.to respond_to :prefix }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    describe '#ndx' do
      it 'is a NdrUint32 structure' do
        expect(packet.ndx).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#prefix' do
      it 'is a OidT' do
        expect(packet.prefix).to be_a RubySMB::Dcerpc::Drsr::OidT
      end
    end
    it 'reads itself' do
      value = {
        ndx: rand(0xFFFFFFFF),
        prefix: {oid_length: 3, elements: [rand(0xFF), rand(0xFF), rand(0xFF)]}
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::PrefixTableEntryArrayPtr  do
    subject(:packet) { described_class.new }

    it 'is a Ndr::NdrConfArray' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrConfArray
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'has elements of type PrefixTableEntry' do
      expect(packet[0]).to be_a RubySMB::Dcerpc::Drsr::PrefixTableEntry
    end
    it 'reads itself' do
      value = [{
        ndx: rand(0xFFFFFFFF),
        prefix: {oid_length: 3, elements: [rand(0xFF), rand(0xFF), rand(0xFF)]}
      }]
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::SchemaPrefixTable  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :prefix_count }
    it { is_expected.to respond_to :p_prefix_entry }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 4-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(4)
    end
    describe '#prefix_count' do
      it 'is a NdrUint32 structure' do
        expect(packet.prefix_count).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
      it 'defaults to the size #p_prefix_entry max_count' do
        packet.p_prefix_entry.max_count = 3
        expect(packet.prefix_count).to eq(3)
      end
    end
    describe '#p_prefix_entry' do
      it 'is a PrefixTableEntryArrayPtr' do
        expect(packet.p_prefix_entry).to be_a RubySMB::Dcerpc::Drsr::PrefixTableEntryArrayPtr
      end
    end
    it 'reads itself' do
      value = {
        prefix_count: 5,
        p_prefix_entry: [{
          ndx: rand(0xFFFFFFFF),
          prefix: {oid_length: 3, elements: [rand(0xFF), rand(0xFF), rand(0xFF)]}
        }]
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::DrsConfStringz do
    subject(:packet) { described_class.new }

    it 'is a Ndr::NdrConfArray' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrConfArray
    end
    it 'has elements of type RubySMB::Dcerpc::Ndr::NdrChar' do
      expect(packet[0]).to be_a RubySMB::Dcerpc::Ndr::NdrChar
    end
    it 'reads itself' do
      value = 'Test String'.chars
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::MtxAddr  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :mtx_name_len }
    it { is_expected.to respond_to :mtx_name }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 4-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(4)
    end
    describe '#mtx_name_len' do
      it 'is a NdrUint32 structure' do
        expect(packet.mtx_name_len).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
      it 'defaults to the length of #mtx_name including the terminating null character' do
        packet.mtx_name = ['A', 'B', 'C', "\x00"]
        expect(packet.mtx_name_len).to eq(4)
      end
    end
    describe '#mtx_name' do
      it 'is a DrsConfStringz' do
        expect(packet.mtx_name).to be_a RubySMB::Dcerpc::Drsr::DrsConfStringz
      end
    end
    it 'reads itself' do
      value = {
        mtx_name_len: 4,
        mtx_name: ['A', 'B', 'C', "\x00"]
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::MtxAddrPtr  do
    subject(:packet) { described_class.new }

    it 'is a MtxAddr' do
      expect(described_class).to be < RubySMB::Dcerpc::Drsr::MtxAddr
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'has a referent which is 4-bytes aligned' do
      expect(packet.eval_parameter(:referent_byte_align)).to eq(4)
    end
    it 'reads itself' do
      value = {
        mtx_name_len: 4,
        mtx_name: ['A', 'B', 'C', "\x00"]
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::VarSizeBufferWithVersion  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :ul_version }
    it { is_expected.to respond_to :cb_byte_buffer }
    it { is_expected.to respond_to :ul_padding }
    it { is_expected.to respond_to :rg_buffer }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 8-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(8)
    end
    describe '#ul_version' do
      it 'is a NdrUint32 structure' do
        expect(packet.ul_version).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#cb_byte_buffer' do
      it 'is a NdrUint32 structure' do
        expect(packet.cb_byte_buffer).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
      it 'defaults to the length of #rg_buffer' do
        packet.rg_buffer = [rand(0xFF)] * 4
        expect(packet.cb_byte_buffer).to eq(4)
      end
    end
    describe '#ul_padding' do
      it 'is a NdrUint64 structure' do
        expect(packet.ul_padding).to be_a RubySMB::Dcerpc::Ndr::NdrUint64
      end
    end
    describe '#rg_buffer' do
      it 'is a NdrConfArray structure' do
        expect(packet.rg_buffer).to be_a RubySMB::Dcerpc::Ndr::NdrConfArray
      end
      it 'has elements of type Ndr::NdrUint8' do
        expect(packet.rg_buffer[0]).to be_a RubySMB::Dcerpc::Ndr::NdrUint8
      end
    end
    it 'reads itself' do
      value = {
        ul_version: rand(0xFFFFFFFF),
        cb_byte_buffer: rand(0xFFFFFFFF),
        ul_padding: rand(0xFFFFFFFFFFFFFFFF),
        rg_buffer: [rand(0xFF)] * 4
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::VarSizeBufferWithVersionPtr  do
    subject(:packet) { described_class.new }

    it 'is a VarSizeBufferWithVersion' do
      expect(described_class).to be < RubySMB::Dcerpc::Drsr::VarSizeBufferWithVersion
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'has a referent which is 8-bytes aligned' do
      expect(packet.eval_parameter(:referent_byte_align)).to eq(8)
    end
    it 'reads itself' do
      value = {
        ul_version: rand(0xFFFFFFFF),
        cb_byte_buffer: rand(0xFFFFFFFF),
        ul_padding: rand(0xFFFFFFFFFFFFFFFF),
        rg_buffer: [rand(0xFF)] * 4
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::Attrval  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :val_len }
    it { is_expected.to respond_to :p_val }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 4-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(4)
    end
    describe '#val_len' do
      it 'is a NdrUint32 structure' do
        expect(packet.val_len).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
      it 'defaults to the length of #p_val in bytes' do
        packet.p_val = [rand(0xFF)] * 4
        expect(packet.val_len).to eq(4)
      end
    end
    describe '#p_val' do
      it 'is a DrsByteArrayPtr structure' do
        expect(packet.p_val).to be_a RubySMB::Dcerpc::Drsr::DrsByteArrayPtr
      end
    end
    it 'reads itself' do
      value = {
        val_len: rand(0xFFFFFFFF),
        p_val: [rand(0xFF)] * 4
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::AttrvalArrayPtr  do
    subject(:packet) { described_class.new }

    it 'is a Ndr::NdrConfArray' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrConfArray
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'has elements of type Attrval' do
      expect(packet[0]).to be_a RubySMB::Dcerpc::Drsr::Attrval
    end
    it 'reads itself' do
      value = [{
        val_len: rand(0xFFFFFFFF),
        p_val: [rand(0xFF)] * 4
      }]
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::Attrvalblock  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :val_count }
    it { is_expected.to respond_to :p_aval }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 4-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(4)
    end
    describe '#val_count' do
      it 'is a NdrUint32' do
        expect(packet.val_count).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
      it 'defaults to the size of #p_aval' do
        packet.p_aval = [{p_val: [rand(0xFF)] * 4}] * 6
        expect(packet.val_count).to eq(6)
      end
    end
    describe '#p_aval' do
      it 'is a AttrvalArrayPtr structure' do
        expect(packet.p_aval).to be_a RubySMB::Dcerpc::Drsr::AttrvalArrayPtr
      end
    end
    it 'reads itself' do
      value = {
        val_count: rand(0xFFFFFFFF),
        p_aval: [{val_len: 4, p_val: [rand(0xFF)] * 4}] * 6
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::Attr  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :attr_typ }
    it { is_expected.to respond_to :attr_val }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 4-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(4)
    end
    describe '#attr_typ' do
      it 'is a Attrtyp structure' do
        expect(packet.attr_typ).to be_a RubySMB::Dcerpc::Drsr::Attrtyp
      end
    end
    describe '#attr_val' do
      it 'is a Attrvalblock structure' do
        expect(packet.attr_val).to be_a RubySMB::Dcerpc::Drsr::Attrvalblock
      end
    end
    it 'reads itself' do
      value = {
        attr_typ: rand(0xFFFFFFFF),
        attr_val: {
          val_count: rand(0xFFFFFFFF),
          p_aval: [{val_len: 4, p_val: [rand(0xFF)] * 4}] * 6
        }
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::AttrArrayPtr  do
    subject(:packet) { described_class.new }

    it 'is a Ndr::NdrConfArray' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrConfArray
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'has elements of type Attr' do
      expect(packet[0]).to be_a RubySMB::Dcerpc::Drsr::Attr
    end
    it 'reads itself' do
      value = [{
        attr_typ: rand(0xFFFFFFFF),
        attr_val: {
          val_count: rand(0xFFFFFFFF),
          p_aval: [{val_len: 4, p_val: [rand(0xFF)] * 4}] * 6
        }
      }]
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::Attrblock  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :attr_count }
    it { is_expected.to respond_to :p_attr }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 4-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(4)
    end
    describe '#attr_count' do
      it 'is a NdrUint32' do
        expect(packet.attr_count).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
      it 'defaults to the size of #p_attr' do
        packet.p_attr = [{ attr_typ: rand(0xFFFFFFFF) }] * 6
        expect(packet.attr_count).to eq(6)
      end
    end
    describe '#p_attr' do
      it 'is a AttrArrayPtr structure' do
        expect(packet.p_attr).to be_a RubySMB::Dcerpc::Drsr::AttrArrayPtr
      end
    end
    it 'reads itself' do
      value = {
        attr_count: rand(0xFFFFFFFF),
        p_attr: [{
          attr_typ: rand(0xFFFFFFFF),
          attr_val: {
            val_count: rand(0xFFFFFFFF),
            p_aval: [{val_len: 4, p_val: [rand(0xFF)] * 4}] * 6
          }
        }]
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::Entinf  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :p_name }
    it { is_expected.to respond_to :ul_flags }
    it { is_expected.to respond_to :attr_block }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 4-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(4)
    end
    describe '#p_name' do
      it 'is a DsNamePtr' do
        expect(packet.p_name).to be_a RubySMB::Dcerpc::Drsr::DsNamePtr
      end
    end
    describe '#ul_flags' do
      it 'is a NdrUint32' do
        expect(packet.ul_flags).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#attr_block' do
      it 'is a Attrblock structure' do
        expect(packet.attr_block).to be_a RubySMB::Dcerpc::Drsr::Attrblock
      end
    end
    it 'reads itself' do
      value = {
        p_name: {
          struct_len: rand(0xFFFFFFFF),
          sid_len: rand(0xFFFFFFFF),
          guid: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
          sid: 'A' * 28,
          name_len: 10,
          string_name: 'Test string'.encode('utf-16le').chars
        },
        ul_flags: rand(0xFFFFFFFF),
        attr_block: {
          attr_count: rand(0xFFFFFFFF),
          p_attr: [{
            attr_typ: rand(0xFFFFFFFF),
            attr_val: {
              val_count: rand(0xFFFFFFFF),
              p_aval: [{val_len: 4, p_val: [rand(0xFF)] * 4}] * 6
            }
          }]
        }
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::Dstime do
    subject(:packet) { described_class.new }

    it 'is a BinData::Int64le' do
      expect(described_class).to be < BinData::Int64le
    end
    it 'is 8-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(8)
    end
    it 'reads itself' do
      value = rand(0xFFFFFFFF)
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::PropertyMetaDataExt  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :dw_version }
    it { is_expected.to respond_to :time_changed }
    it { is_expected.to respond_to :uuid_dsa_originating }
    it { is_expected.to respond_to :usn_originating }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 8-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(8)
    end
    describe '#dw_version' do
      it 'is a NdrUint32' do
        expect(packet.dw_version).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#time_changed' do
      it 'is a Dstime structure' do
        expect(packet.time_changed).to be_a RubySMB::Dcerpc::Drsr::Dstime
      end
    end
    describe '#uuid_dsa_originating' do
      it 'is a Uuid structure' do
        expect(packet.uuid_dsa_originating).to be_a RubySMB::Dcerpc::Uuid
      end
    end
    describe '#usn_originating' do
      it 'is a Usn structure' do
        expect(packet.usn_originating).to be_a RubySMB::Dcerpc::Drsr::Usn
      end
    end
    it 'reads itself' do
      value = {
        dw_version: rand(0xFFFFFFFF),
        time_changed: rand(0xFFFFFFFF),
        uuid_dsa_originating: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
        usn_originating: rand(0xFFFFFFFF),
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::PropertyMetaDataExtVector  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :c_num_props }
    it { is_expected.to respond_to :rg_meta_data }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 8-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(8)
    end
    describe '#c_num_props' do
      it 'is a NdrUint32' do
        expect(packet.c_num_props).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
      it 'defaults to the size of #rg_meta_data' do
        packet.rg_meta_data = [RubySMB::Dcerpc::Drsr::PropertyMetaDataExt.new] * 4
        expect(packet.c_num_props).to eq(4)
      end
    end
    describe '#rg_meta_data' do
      it 'is a NdrConfArray structure' do
        expect(packet.rg_meta_data).to be_a RubySMB::Dcerpc::Ndr::NdrConfArray
      end
      it 'has elements of type PropertyMetaDataExt' do
        expect(packet.rg_meta_data[0]).to be_a RubySMB::Dcerpc::Drsr::PropertyMetaDataExt
      end
    end
    it 'reads itself' do
      value = {
        c_num_props: rand(0xFFFFFFFF),
        rg_meta_data: [{
          dw_version: rand(0xFFFFFFFF),
          time_changed: rand(0xFFFFFFFF),
          uuid_dsa_originating: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
          usn_originating: rand(0xFFFFFFFF),
        }]
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::PropertyMetaDataExtVectorPtr  do
    subject(:packet) { described_class.new }

    it 'is a PropertyMetaDataExtVector' do
      expect(described_class).to be < RubySMB::Dcerpc::Drsr::PropertyMetaDataExtVector
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'has a referent which is 8-bytes aligned' do
      expect(packet.eval_parameter(:referent_byte_align)).to eq(8)
    end
    it 'reads itself' do
      value = {
        c_num_props: rand(0xFFFFFFFF),
        rg_meta_data: [{
          dw_version: rand(0xFFFFFFFF),
          time_changed: rand(0xFFFFFFFF),
          uuid_dsa_originating: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
          usn_originating: rand(0xFFFFFFFF),
        }]
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::ReplentinflistPtr  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :p_next_ent_inf }
    it { is_expected.to respond_to :entinf }
    it { is_expected.to respond_to :f_is_nc_prefix }
    it { is_expected.to respond_to :p_parent_guid }
    it { is_expected.to respond_to :p_meta_data_ext }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'is 4-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(4)
    end
    it 'has a referent which is 4-bytes aligned' do
      expect(packet.eval_parameter(:referent_byte_align)).to eq(4)
    end
    describe '#p_next_ent_inf' do
      it 'is a ReplentinflistPtr structure' do
        expect(packet.p_next_ent_inf).to be_a RubySMB::Dcerpc::Drsr::ReplentinflistPtr
      end
    end
    describe '#entinf' do
      it 'is a Entinf structure' do
        expect(packet.entinf).to be_a RubySMB::Dcerpc::Drsr::Entinf
      end
    end
    describe '#f_is_nc_prefix' do
      it 'is a Ndr::NdrBoolean structure' do
        expect(packet.f_is_nc_prefix).to be_a RubySMB::Dcerpc::Ndr::NdrBoolean
      end
    end
    describe '#p_parent_guid' do
      it 'is a UuidPtr structure' do
        expect(packet.p_parent_guid).to be_a RubySMB::Dcerpc::Ndr::UuidPtr
      end
    end
    describe '#p_meta_data_ext' do
      it 'is a PropertyMetaDataExtVector structure' do
        expect(packet.p_meta_data_ext).to be_a RubySMB::Dcerpc::Drsr::PropertyMetaDataExtVector
      end
    end
    it 'reads itself' do
      value = {
        p_next_ent_inf: :null,
        entinf: {
          p_name: {
            struct_len: rand(0xFFFFFFFF),
            sid_len: rand(0xFFFFFFFF),
            guid: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
            sid: 'A' * 28,
            name_len: 10,
            string_name: 'Test string'.encode('utf-16le').chars
          },
          ul_flags: rand(0xFFFFFFFF),
          attr_block: {
            attr_count: rand(0xFFFFFFFF),
            p_attr: [{
              attr_typ: rand(0xFFFFFFFF),
              attr_val: {
                val_count: rand(0xFFFFFFFF),
                p_aval: [{val_len: 4, p_val: [rand(0xFF)] * 4}] * 6
              }
            }]
          }
        },
        f_is_nc_prefix: true,
        p_parent_guid: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
        p_meta_data_ext: {
          c_num_props: rand(0xFFFFFFFF),
          rg_meta_data: [{
            dw_version: rand(0xFFFFFFFF),
            time_changed: rand(0xFFFFFFFF),
            uuid_dsa_originating: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
            usn_originating: rand(0xFFFFFFFF),
          }]
        }
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::DrsCompressedBlob  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :cb_uncompressed_size }
    it { is_expected.to respond_to :cb_compressed_size }
    it { is_expected.to respond_to :pb_compressed_data }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 4-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(4)
    end
    describe '#cb_uncompressed_size' do
      it 'is a Ndr::NdrUint32 structure' do
        expect(packet.cb_uncompressed_size).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#cb_compressed_size' do
      it 'is a Ndr::NdrUint32 structure' do
        expect(packet.cb_compressed_size).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#pb_compressed_data' do
      it 'is a Ndr::NdrConfArray' do
        expect(packet.pb_compressed_data).to be_a RubySMB::Dcerpc::Ndr::NdrConfArray
      end
      it 'has elements of type Ndr::NdrUint8' do
        expect(packet.pb_compressed_data[0]).to be_a RubySMB::Dcerpc::Ndr::NdrUint8
      end
    end
    it 'reads itself' do
      value = {
        cb_uncompressed_size: rand(0xFFFFFFFF),
        cb_compressed_size: rand(0xFFFFFFFF),
        pb_compressed_data: [rand(0xFF)] * 4
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::ValueMetaDataExtV1  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :time_created }
    it { is_expected.to respond_to :meta_data }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 8-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(8)
    end
    describe '#time_created' do
      it 'is a Dstime' do
        expect(packet.time_created).to be_a RubySMB::Dcerpc::Drsr::Dstime
      end
    end
    describe '#meta_data' do
      it 'is a PropertyMetaDataExt' do
        expect(packet.meta_data).to be_a RubySMB::Dcerpc::Drsr::PropertyMetaDataExt
      end
    end
    it 'reads itself' do
      value = {
        time_created: rand(0xFFFFFFFF),
        meta_data:  {
          dw_version: rand(0xFFFFFFFF),
          time_changed: rand(0xFFFFFFFF),
          uuid_dsa_originating: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
          usn_originating: rand(0xFFFFFFFF),
        }
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::ReplvalinfV1  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :p_object }
    it { is_expected.to respond_to :attr_typ }
    it { is_expected.to respond_to :aval }
    it { is_expected.to respond_to :f_is_present }
    it { is_expected.to respond_to :meta_data }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 8-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(8)
    end
    describe '#p_object' do
      it 'is a DsNamePtr structure' do
        expect(packet.p_object).to be_a RubySMB::Dcerpc::Drsr::DsNamePtr
      end
    end
    describe '#attr_typ' do
      it 'is a Attrtyp structure' do
        expect(packet.attr_typ).to be_a RubySMB::Dcerpc::Drsr::Attrtyp
      end
    end
    describe '#aval' do
      it 'is a Attrval structure' do
        expect(packet.aval).to be_a RubySMB::Dcerpc::Drsr::Attrval
      end
    end
    describe '#f_is_present' do
      it 'is a Ndr::NdrBoolean structure' do
        expect(packet.f_is_present).to be_a RubySMB::Dcerpc::Ndr::NdrBoolean
      end
    end
    describe '#meta_data' do
      it 'is a ValueMetaDataExtV1 structure' do
        expect(packet.meta_data).to be_a RubySMB::Dcerpc::Drsr::ValueMetaDataExtV1
      end
    end
    it 'reads itself' do
      value = {
        p_object: {
          struct_len: rand(0xFFFFFFFF),
          sid_len: rand(0xFFFFFFFF),
          guid: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
          sid: 'A' * 28,
          name_len: 10,
          string_name: 'Test string'.encode('utf-16le').chars
        },
        attr_typ: rand(0xFFFFFFFF),
        aval: {
          val_len: rand(0xFFFFFFFF),
          p_val: [rand(0xFF)] * 4
        },
        f_is_present: true,
        meta_data: {
          time_created: rand(0xFFFFFFFF),
          meta_data:  {
            dw_version: rand(0xFFFFFFFF),
            time_changed: rand(0xFFFFFFFF),
            uuid_dsa_originating: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
            usn_originating: rand(0xFFFFFFFF),
          }
        }
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::ReplvalinfV1ArrayPtr  do
    subject(:packet) { described_class.new }

    it 'is a Ndr::NdrConfArray' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrConfArray
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'has elements of type ReplvalinfV1' do
      expect(packet[0]).to be_a RubySMB::Dcerpc::Drsr::ReplvalinfV1
    end
    it 'reads itself' do
      value = [{
        p_object: {
          struct_len: rand(0xFFFFFFFF),
          sid_len: rand(0xFFFFFFFF),
          guid: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
          sid: 'A' * 28,
          name_len: 10,
          string_name: 'Test string'.encode('utf-16le').chars
        },
        attr_typ: rand(0xFFFFFFFF),
        aval: {
          val_len: rand(0xFFFFFFFF),
          p_val: [rand(0xFF)] * 4
        },
        f_is_present: true,
        meta_data: {
          time_created: rand(0xFFFFFFFF),
          meta_data:  {
            dw_version: rand(0xFFFFFFFF),
            time_changed: rand(0xFFFFFFFF),
            uuid_dsa_originating: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
            usn_originating: rand(0xFFFFFFFF),
          }
        }
      }]
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::DrsCompAlgType do
    it 'is a Ndr::NdrUint32' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end

  describe described_class::ValueMetaDataExtV3  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :time_created }
    it { is_expected.to respond_to :meta_data }
    it { is_expected.to respond_to :unused1 }
    it { is_expected.to respond_to :unused2 }
    it { is_expected.to respond_to :unused3 }
    it { is_expected.to respond_to :time_expired }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 8-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(8)
    end
    describe '#time_created' do
      it 'is a Dstime'do
        expect(packet.time_created).to be_a RubySMB::Dcerpc::Drsr::Dstime
      end
    end
    describe '#meta_data' do
      it 'is a PropertyMetaDataExt structure' do
        expect(packet.meta_data).to be_a RubySMB::Dcerpc::Drsr::PropertyMetaDataExt
      end
    end
    describe '#unused1' do
      it 'is a Ndr::NdrUint32 structure' do
        expect(packet.unused1).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#unused2' do
      it 'is a Ndr::NdrUint32 structure' do
        expect(packet.unused2).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#unused3' do
      it 'is a Ndr::NdrUint32 structure' do
        expect(packet.unused3).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#time_expired' do
      it 'is a Dstime'do
        expect(packet.time_expired).to be_a RubySMB::Dcerpc::Drsr::Dstime
      end
    end
    it 'reads itself' do
      value = {
        time_created: rand(0xFFFFFFFF),
        meta_data: {
          dw_version: rand(0xFFFFFFFF),
          time_changed: rand(0xFFFFFFFF),
          uuid_dsa_originating: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
          usn_originating: rand(0xFFFFFFFF),
        },
        unused1: rand(0xFFFFFFFF),
        unused2: rand(0xFFFFFFFF),
        unused3: rand(0xFFFFFFFF),
        time_expired: rand(0xFFFFFFFF)
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::ReplvalinfV3  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :p_object }
    it { is_expected.to respond_to :attr_typ }
    it { is_expected.to respond_to :aval }
    it { is_expected.to respond_to :f_is_present }
    it { is_expected.to respond_to :meta_data }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 8-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(8)
    end
    describe '#p_object' do
      it 'is a DsNamePtr structure' do
        expect(packet.p_object).to be_a RubySMB::Dcerpc::Drsr::DsNamePtr
      end
    end
    describe '#attr_typ' do
      it 'is a Attrtyp structure' do
        expect(packet.attr_typ).to be_a RubySMB::Dcerpc::Drsr::Attrtyp
      end
    end
    describe '#aval' do
      it 'is a Attrval structure' do
        expect(packet.aval).to be_a RubySMB::Dcerpc::Drsr::Attrval
      end
    end
    describe '#f_is_present' do
      it 'is a Ndr::NdrBoolean structure' do
        expect(packet.f_is_present).to be_a RubySMB::Dcerpc::Ndr::NdrBoolean
      end
    end
    describe '#meta_data' do
      it 'is a ValueMetaDataExtV3 structure' do
        expect(packet.meta_data).to be_a RubySMB::Dcerpc::Drsr::ValueMetaDataExtV3
      end
    end
    it 'reads itself' do
      value = {
        p_object: {
          struct_len: rand(0xFFFFFFFF),
          sid_len: rand(0xFFFFFFFF),
          guid: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
          sid: 'A' * 28,
          name_len: 10,
          string_name: 'Test string'.encode('utf-16le').chars
        },
        attr_typ: rand(0xFFFFFFFF),
        aval: {
          val_len: rand(0xFFFFFFFF),
          p_val: [rand(0xFF)] * 4
        },
        f_is_present: true,
        meta_data: {
          time_created: rand(0xFFFFFFFF),
          meta_data: {
            dw_version: rand(0xFFFFFFFF),
            time_changed: rand(0xFFFFFFFF),
            uuid_dsa_originating: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
            usn_originating: rand(0xFFFFFFFF),
          },
          unused1: rand(0xFFFFFFFF),
          unused2: rand(0xFFFFFFFF),
          unused3: rand(0xFFFFFFFF),
          time_expired: rand(0xFFFFFFFF)
        }
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::ReplvalinfV3ArrayPtr  do
    subject(:packet) { described_class.new }

    it 'is a Ndr::NdrConfArray' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrConfArray
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'has elements of type ReplvalinfV3' do
      expect(packet[0]).to be_a RubySMB::Dcerpc::Drsr::ReplvalinfV3
    end
    it 'reads itself' do
      value = [{
        p_object: {
          struct_len: rand(0xFFFFFFFF),
          sid_len: rand(0xFFFFFFFF),
          guid: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
          sid: 'A' * 28,
          name_len: 10,
          string_name: 'Test string'.encode('utf-16le').chars
        },
        attr_typ: rand(0xFFFFFFFF),
        aval: {
          val_len: rand(0xFFFFFFFF),
          p_val: [rand(0xFF)] * 4
        },
        f_is_present: true,
        meta_data: {
          time_created: rand(0xFFFFFFFF),
          meta_data: {
            dw_version: rand(0xFFFFFFFF),
            time_changed: rand(0xFFFFFFFF),
            uuid_dsa_originating: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
            usn_originating: rand(0xFFFFFFFF),
          },
          unused1: rand(0xFFFFFFFF),
          unused2: rand(0xFFFFFFFF),
          unused3: rand(0xFFFFFFFF),
          time_expired: rand(0xFFFFFFFF)
        }
      }]
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::UptodateCursorV2  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :uuid_dsa }
    it { is_expected.to respond_to :usn_high_prop_update }
    it { is_expected.to respond_to :time_last_sync_success }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 8-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(8)
    end
    describe '#uuid_dsa' do
      it 'is a Uuid structure' do
        expect(packet.uuid_dsa).to be_a RubySMB::Dcerpc::Uuid
      end
    end
    describe '#usn_high_prop_update' do
      it 'is a Usn structure' do
        expect(packet.usn_high_prop_update).to be_a RubySMB::Dcerpc::Drsr::Usn
      end
    end
    describe '#time_last_sync_success' do
      it 'is a Dstime structure' do
        expect(packet.time_last_sync_success).to be_a RubySMB::Dcerpc::Drsr::Dstime
      end
    end
    it 'reads itself' do
      value = {
        uuid_dsa: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
        usn_high_prop_update: rand(0xFFFFFFFF),
        time_last_sync_success: rand(0xFFFFFFFF)
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::UptodateVectorV2Ext  do
    subject(:packet) { described_class.new }

    it { is_expected.to respond_to :dw_version }
    it { is_expected.to respond_to :dw_reserved1 }
    it { is_expected.to respond_to :c_num_cursors }
    it { is_expected.to respond_to :dw_reserved2 }
    it { is_expected.to respond_to :rg_cursors }

    it 'is a Ndr::NdrStruct' do
      expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrStruct
    end
    it 'is 8-bytes aligned' do
      expect(packet.eval_parameter(:byte_align)).to eq(8)
    end
    describe '#dw_version' do
      it 'is a NdrUint32 structure' do
        expect(packet.dw_version).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#dw_reserved1' do
      it 'is a NdrUint32 structure' do
        expect(packet.dw_reserved1).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#c_num_cursors' do
      it 'is a NdrUint32 structure' do
        expect(packet.c_num_cursors).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#dw_reserved2' do
      it 'is a NdrUint32 structure' do
        expect(packet.dw_reserved2).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
      end
    end
    describe '#rg_cursors' do
      it 'is a NdrConfArray structure' do
        expect(packet.rg_cursors).to be_a RubySMB::Dcerpc::Ndr::NdrConfArray
      end
      it 'has elements of type UptodateCursorV2' do
        expect(packet.rg_cursors[0]).to be_a RubySMB::Dcerpc::Drsr::UptodateCursorV2
      end
    end
    it 'reads itself' do
      value = {
        dw_version: rand(0xFFFFFFFF),
        dw_reserved1: rand(0xFFFFFFFF),
        c_num_cursors: rand(0xFFFFFFFF),
        dw_reserved2: rand(0xFFFFFFFF),
        rg_cursors: [{
          uuid_dsa: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
          usn_high_prop_update: rand(0xFFFFFFFF),
          time_last_sync_success: rand(0xFFFFFFFF)
        }]
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe described_class::UptodateVectorV2ExtPtr  do
    subject(:packet) { described_class.new }

    it 'is a UptodateVectorV2Ext' do
      expect(described_class).to be < RubySMB::Dcerpc::Drsr::UptodateVectorV2Ext
    end
    it 'is a NdrPointer' do
      expect(described_class).to be_a(RubySMB::Dcerpc::Ndr::PointerClassPlugin)
      expect(packet).to be_a(RubySMB::Dcerpc::Ndr::PointerPlugin)
    end
    it 'has a referent which is 8-bytes aligned' do
      expect(packet.eval_parameter(:referent_byte_align)).to eq(8)
    end
    it 'reads itself' do
      value = {
        dw_version: rand(0xFFFFFFFF),
        dw_reserved1: rand(0xFFFFFFFF),
        c_num_cursors: rand(0xFFFFFFFF),
        dw_reserved2: rand(0xFFFFFFFF),
        rg_cursors: [{
          uuid_dsa: 'ee1ecfe6-109d-11ec-82a8-0242ac130003',
          usn_high_prop_update: rand(0xFFFFFFFF),
          time_last_sync_success: rand(0xFFFFFFFF)
        }]
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe '#drs_bind' do
    let(:method) { [:drs_bind] }
    let(:request_struct) { described_class::DrsBindRequest }
    let(:response_struct) { described_class::DrsBindResponse }
    let(:values) do
      {
        pext_client: {
          dw_flags: described_class::DRS_EXT_GETCHGREQ_V6 |
                    described_class::DRS_EXT_GETCHGREPLY_V6 |
                    described_class::DRS_EXT_GETCHGREQ_V8 |
                    described_class::DRS_EXT_STRONG_ENCRYPTION,
          dw_ext_caps: 0xFFFFFFFF
        }
      }
    end
    let(:request) { request_struct.new(values) }
    let(:response) { response_struct.new }
    before :example do
      allow(drsr).to receive(:dcerpc_request).and_return(response.to_binary_s)
      allow(response_struct).to receive(:read).and_return(response)
    end

    it 'sends the correct request packet with authentication parameters' do
      drsr.send(*method)
      expect(drsr).to have_received(:dcerpc_request).with(
        request,
        auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
      )
    end
    it 'receives the expected response' do
      drsr.send(*method)
      expect(response_struct).to have_received(:read).with(response.to_binary_s)
    end
    context 'with an invalid response' do
      it 'raise an InvalidPacket exception' do
        allow(response_struct).to receive(:read).and_raise(IOError)
        expect { drsr.send(*method) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end
    context 'when the response status is not STATUS_SUCCESS' do
      it 'raise an DrsrError exception' do
        response.error_status = WindowsError::NTStatus::STATUS_ACCESS_DENIED.value
        expect { drsr.send(*method) }.to raise_error(RubySMB::Dcerpc::Error::DrsrError)
      end
    end
    it 'returns the correct handle' do
      handle = {context_handle_attributes: rand(0xFF), context_handle_uuid: '57800405-0301-3330-5566-040023007000'}
      response.ph_drs = handle
      expect(drsr.send(*method)).to eq(handle)
    end
    context 'with a different epoch in the response' do
      before :example do
        drs_ext = described_class::DrsExtensionsInt.new(dw_repl_epoch: 444)
        response.ppext_server = drs_ext
      end

      it 'calls DRSBind again with the correct epoch' do

        drs_ext2 = described_class::DrsExtensionsInt.new(
          dw_flags: described_class::DRS_EXT_GETCHGREQ_V6 |
                    described_class::DRS_EXT_GETCHGREPLY_V6 |
                    described_class::DRS_EXT_GETCHGREQ_V8 |
                    described_class::DRS_EXT_STRONG_ENCRYPTION,
          dw_ext_caps: 0xFFFFFFFF,
          dw_repl_epoch: 444
        )
        request2 = request_struct.new(values)
        request2.pext_client = drs_ext2

        expect(drsr).to receive(:dcerpc_request).with(
          request,
          auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
          auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
        ).ordered
        expect(drsr).to receive(:dcerpc_request).once.with(
          request2,
          auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
          auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
        ).ordered

        drsr.send(*method)
      end
      it 'returns the correct handle' do
        handle = {context_handle_attributes: rand(0xFF), context_handle_uuid: '57800405-0301-3330-5566-040023007000'}
        second = false
        allow(described_class::DrsBindResponse).to receive(:read) do
          response.ph_drs = handle if second
          second = true
          response
        end
        expect(drsr.send(*method)).to eq(handle)
      end
    end
  end

  describe '#drs_unbind' do
    let(:ph_drs) { handle = {context_handle_attributes: rand(0xFF), context_handle_uuid: '57800405-0301-3330-5566-040023007000'} }
    let(:method) { [:drs_unbind, ph_drs] }
    let(:request_struct) { described_class::DrsUnbindRequest }
    let(:response_struct) { described_class::DrsUnbindResponse }
    let(:values) { { ph_drs: ph_drs } }
    let(:request) { request_struct.new(values) }
    let(:response) { response_struct.new }
    before :example do
      allow(drsr).to receive(:dcerpc_request).and_return(response.to_binary_s)
      allow(response_struct).to receive(:read).and_return(response)
    end

    it 'sends the correct request packet with authentication parameters' do
      drsr.send(*method)
      expect(drsr).to have_received(:dcerpc_request).with(
        request,
        auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
      )
    end
    it 'receives the expected response' do
      drsr.send(*method)
      expect(response_struct).to have_received(:read).with(response.to_binary_s)
    end
    context 'with an invalid response' do
      it 'raise an InvalidPacket exception' do
        allow(response_struct).to receive(:read).and_raise(IOError)
        expect { drsr.send(*method) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end
    context 'when the response status is not STATUS_SUCCESS' do
      it 'raise an DrsrError exception' do
        response.error_status = WindowsError::NTStatus::STATUS_ACCESS_DENIED.value
        expect { drsr.send(*method) }.to raise_error(RubySMB::Dcerpc::Error::DrsrError)
      end
    end
  end

  describe '#drs_domain_controller_info' do
    let(:h_drs) { handle = {context_handle_attributes: rand(0xFF), context_handle_uuid: '57800405-0301-3330-5566-040023007000'} }
    let(:domain) { 'rubysmb.local' }
    let(:method) { [:drs_domain_controller_info, h_drs, domain] }
    let(:request_struct) { described_class::DrsDomainControllerInfoRequest }
    let(:response_struct) { described_class::DrsDomainControllerInfoResponse }
    let(:values) do
      {
        h_drs: h_drs,
        pmsg_in: {
          switch_type: 1,
          msg_dcinfo: {
            domain: domain,
            info_level: 2
          }
        }
      }
    end
    let(:request) { request_struct.new(values) }
    let(:response) { response_struct.new(pmsg_out: {switch_type: 2}) }
    before :example do
      allow(drsr).to receive(:dcerpc_request).and_return(response.to_binary_s)
      allow(response_struct).to receive(:read).and_return(response)
    end

    it 'sends the correct request packet with authentication parameters' do
      drsr.send(*method)
      expect(drsr).to have_received(:dcerpc_request).with(
        request,
        auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
      )
    end
    it 'receives the expected response' do
      drsr.send(*method)
      expect(response_struct).to have_received(:read).with(response.to_binary_s)
    end
    context 'with an invalid response' do
      it 'raise an InvalidPacket exception' do
        allow(response_struct).to receive(:read).and_raise(IOError)
        expect { drsr.send(*method) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end
    context 'when the response status is not STATUS_SUCCESS' do
      it 'raise an DrsrError exception' do
        response.error_status = WindowsError::NTStatus::STATUS_ACCESS_DENIED.value
        expect { drsr.send(*method) }.to raise_error(RubySMB::Dcerpc::Error::DrsrError)
      end
    end
    it 'returns the correct array of domain controller infos' do
      info_array = [
        described_class::DsDomainControllerInfo2w.new(computer_object_name: random_str),
        described_class::DsDomainControllerInfo2w.new(computer_object_name: random_str),
        described_class::DsDomainControllerInfo2w.new(computer_object_name: random_str)
      ]
      response.pmsg_out.msg_dcinfo.r_items = info_array
      expect(drsr.send(*method)).to be_a ::Array
      expect(drsr.send(*method)).to eq(info_array)
    end
  end

  describe '#drs_crack_names' do
    let(:h_drs) { handle = {context_handle_attributes: rand(0xFF), context_handle_uuid: '57800405-0301-3330-5566-040023007000'} }
    let(:domain) { 'rubysmb.local' }
    let(:method) { [ :drs_crack_names, h_drs ] }
    let(:request_struct) { described_class::DrsCrackNamesRequest }
    let(:response_struct) { described_class::DrsCrackNamesResponse }
    let(:flags) { 0 }
    let(:format_offered) { described_class::DS_SID_OR_SID_HISTORY_NAME }
    let(:format_desired) { described_class::DS_UNIQUE_ID_NAME }
    let(:rp_names) { [] }
    let(:values) do
      {
        h_drs: h_drs,
        pmsg_in: {
          switch_type: 1,
          msg_crack: {
            dw_flags: flags,
            format_offered: format_offered,
            format_desired: format_desired,
            rp_names: rp_names
          }
        }
      }
    end
    let(:request) { request_struct.new(values) }
    let(:response) { response_struct.new(pmsg_out: {switch_type: 1}) }
    before :example do
      allow(drsr).to receive(:dcerpc_request).and_return(response.to_binary_s)
      allow(response_struct).to receive(:read).and_return(response)
    end

    it 'sends the correct request packet with authentication parameters' do
      drsr.send(*method)
      expect(drsr).to have_received(:dcerpc_request).with(
        request,
        auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
      )
    end
    context 'when passing specific values as arguments' do
      let(:flags) { rand(0xFF) }
      let(:format_offered) { described_class::DS_USER_PRINCIPAL_NAME }
      let(:format_desired) { described_class::DS_USER_PRINCIPAL_NAME }
      let(:rp_names) { ['Test1', 'Test2'] }
      it 'sends the correct request packet with authentication parameters' do
        drsr.send(*method, {flags: flags, format_offered: format_offered, format_desired: format_desired, rp_names: rp_names})
        expect(drsr).to have_received(:dcerpc_request).with(
          request,
          auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
          auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
        )
      end
    end
    it 'receives the expected response' do
      drsr.send(*method)
      expect(response_struct).to have_received(:read).with(response.to_binary_s)
    end
    context 'with an invalid response' do
      it 'raise an InvalidPacket exception' do
        allow(response_struct).to receive(:read).and_raise(IOError)
        expect { drsr.send(*method) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end
    context 'when the response status is not STATUS_SUCCESS' do
      it 'raise an DrsrError exception' do
        response.error_status = WindowsError::NTStatus::STATUS_ACCESS_DENIED.value
        expect { drsr.send(*method) }.to raise_error(RubySMB::Dcerpc::Error::DrsrError)
      end
    end
    it 'returns the correct array of translated names' do
      name_array = [
        described_class::DsNameResultItemw.new(p_domain: random_str),
        described_class::DsNameResultItemw.new(p_domain: random_str),
        described_class::DsNameResultItemw.new(p_domain: random_str)
      ]
      response.pmsg_out.msg_crack.p_result.r_items = name_array
      expect(drsr.send(*method)).to be_a ::Array
      expect(drsr.send(*method)).to eq(name_array)
    end
  end

  describe described_class::EncryptedPayload do
    subject(:packet) { described_class.new }

    it 'is a BinData::Record' do
      expect(described_class).to be < BinData::Record
    end
    it 'is little endian' do
      expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
    end

    it { is_expected.to respond_to :salt }
    it { is_expected.to respond_to :check_sum }
    it { is_expected.to respond_to :encrypted_data }

    describe '#salt' do
      it 'is a Uint8Array structure' do
        expect(packet.salt).to be_a BinData::Uint8Array
      end
    end
    describe '#check_sum' do
      it 'is a BinData::Uint32le structure' do
        expect(packet.check_sum).to be_a BinData::Uint32le
      end
    end
    describe '#encrypted_data' do
      it 'is a Uint8Array structure' do
        expect(packet.encrypted_data).to be_a BinData::Uint8Array
      end
    end
    it 'reads itself' do
      value = {
        salt: [rand(0xFF)] * 16,
        check_sum: rand(0xFF),
        encrypted_data: [rand(0xFF)] * rand(40)
      }
      new_struct = described_class.new(value)
      expect(packet.read(new_struct.to_binary_s)).to eq(value)
    end
  end

  describe '#decrypt_attribute_value' do
    it 'correctly decrypts the attribute value' do
      drsr.instance_variable_set(:@session_key, 'fd96e4fee462a67f8db319d72fcf818b'.unhexlify)
      attribute = '2302d5755f87896fab6e1dcd63e3b1e7ed4d8e8ebfb29e2bc36580c98d919356d340d442'.unhexlify
      decrypted = '7997edef91334c0182ee1cb5a9757769'.unhexlify
      expect(drsr.decrypt_attribute_value(attribute)).to eq(decrypted)
    end
    context 'when the session key is empty' do
      it 'raise an EncryptionError' do
        expect { drsr.decrypt_attribute_value('AAA') }.to raise_error(RubySMB::Error::EncryptionError)
      end
    end
  end

  describe '#transform_key' do
    it 'correctly transforms the key' do
      input_key = '51040000510400'.unhexlify
      transformed = '5082000004881000'.unhexlify
      expect(drsr.transform_key(input_key)).to eq(transformed)
    end
  end

  describe '#derive_key' do
    it 'correctly derives an unsigned integer into two keys' do
      base_key = 1105
      derived = ['5082000004881000'.unhexlify, '0028408000024408'.unhexlify]
      expect(drsr.derive_key(base_key)).to eq(derived)
    end
  end

  describe '#remove_des_layer' do
    it 'correctly decrypts the hash' do
      crypted_hash = '7997edef91334c0182ee1cb5a9757769'.unhexlify
      rid = 1105
      decrypted = '32ed87bdb5fdc5e9cba88547376818d4'.unhexlify
      expect(drsr.remove_des_layer(crypted_hash, rid)).to eq(decrypted)
    end
  end

  describe '#drs_get_nc_changes' do
    let(:h_drs) { handle = {context_handle_attributes: rand(0xFF), context_handle_uuid: '57800405-0301-3330-5566-040023007000'} }
    let(:nc_guid) { 'ee1ecfe6-109d-11ec-82a8-0242ac130003' }
    let(:dsa_object_guid) { '8609c6ea-8268-4c4f-a08a-001bca9bd1d7' }
    let(:method) { [ :drs_get_nc_changes, h_drs, { nc_guid: nc_guid, dsa_object_guid: dsa_object_guid } ] }
    let(:request_struct) { described_class::DrsGetNcChangesRequest }
    let(:response_struct) { described_class::DrsGetNcChangesResponse }
    let(:values) do
      {
        h_drs: h_drs,
        dw_in_version: 8,
        pmsg_in: {
          msg_getchg: {
            uuid_dsa_obj_dest: dsa_object_guid,
            uuid_invoc_id_src: dsa_object_guid,
            p_nc: {
              guid: nc_guid,
              string_name: ["\0"]
            },
            ul_flags: described_class::DRS_INIT_SYNC | described_class::DRS_WRIT_REP,
            c_max_objects: 1,
            ul_extended_op: described_class::EXOP_REPL_OBJ
          }
        }
      }
    end
    let(:request) { request_struct.new(values) }
    let(:response) { response_struct.new(pmsg_out: {switch_type: 6}) }
    before :example do
      described_class::ATTRTYP_TO_ATTID.values.each do |oid|
        request.pmsg_in.msg_getchg.add_attrtyp_from_oid(oid)
      end
      allow(drsr).to receive(:dcerpc_request).and_return(response.to_binary_s)
      allow(response_struct).to receive(:read).and_return(response)
    end

    it 'sends the correct request packet with authentication parameters' do
      drsr.send(*method)
      expect(drsr).to have_received(:dcerpc_request).with(
        request,
        auth_level: RubySMB::Dcerpc::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        auth_type: RubySMB::Dcerpc::RPC_C_AUTHN_WINNT
      )
    end
    it 'receives the expected response' do
      drsr.send(*method)
      expect(response_struct).to have_received(:read).with(response.to_binary_s)
    end
    context 'with an invalid response' do
      it 'raise an InvalidPacket exception' do
        allow(response_struct).to receive(:read).and_raise(IOError)
        expect { drsr.send(*method) }.to raise_error(RubySMB::Dcerpc::Error::InvalidPacket)
      end
    end
    context 'when the response status is not STATUS_SUCCESS' do
      it 'raise an DrsrError exception' do
        response.error_status = WindowsError::NTStatus::STATUS_ACCESS_DENIED.value
        expect { drsr.send(*method) }.to raise_error(RubySMB::Dcerpc::Error::DrsrError)
      end
    end
    it 'returns the correct DrsGetNcChanges response' do
      expect(drsr.send(*method)).to eq(response)
    end
  end

end

