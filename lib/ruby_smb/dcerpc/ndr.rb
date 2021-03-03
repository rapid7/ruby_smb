# TODO: Add automatic padding (https://github.com/dmendel/bindata/wiki/Records#aligned-fields)
# TODO: Make offset editable for conformant structures (array and string)

module RubySMB::Dcerpc::Ndr

  # NDR Syntax
  UUID = '8a885d04-1ceb-11c9-9fe8-08002b104860'
  VER_MAJOR = 2
  VER_MINOR = 0

  #####################################
  #        NDR Primitive Types        #
  #####################################

  # Signed and unsigned integers use BinData primitives directly

  # [Booleans](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_02_03)
  class Boolean < BinData::Uint32le
    def assign(val)
      super(value_to_int(val))
    end

    def snapshot
      return _value == 0 ? false : true
    end


    private

    def value_to_binary_string(val)
      super(value_to_int(val))
    end

    def value_to_int(val)
      case(val)
      when FalseClass
        return 0
      when TrueClass
        return 1
      when Integer
        # Any non-zero value is TRUE, let's assume the caller knows what he's doing
        return val
      else
        raise ArgumentError.new(
          "Type mismatch (#{val.class}). Expecting FalseClass, TrueClass or Integer"
        )
      end
    end
  end

  # [Characters](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_02_04)
  class Char < BinData::String
    default_parameter length: 1
  end
  class WideChar < RubySMB::Field::String16
    default_parameter length: 2
  end
  #class Char < BinData::Uint8
  #  def assign(val)
  #    super(char_to_int(val))
  #  end

  #  def snapshot
  #    return _value.chr
  #  end


  #  private

  #  def value_to_binary_string(val)
  #    super(char_to_int(val))
  #  end

  #  def char_to_int(val)
  #    case(val)
  #    when String
  #      return val[0].ord
  #    when Integer
  #      return val
  #    else
  #      raise ArgumentError.new(
  #        "Type mismatch (#{val.class}). Expecting Character or Integer"
  #      )
  #    end
  #  end
  #end

  # An NDR Enum type as defined in
  # [Transfer Syntax NDR - Enumerated Types](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_02_05_01)
  class NdrEnum < BinData::Int16le; end




  #####################################
  #       NDR Constructed Types       #
  #####################################


  #
  # Arrays
  #
  module ArrayPlugin
    def do_write(io)
      if is_array_of_pointers
        super(io, in_array_ptr: true)
        write_ptr(io)
      else
        super
      end
    end

    def write_ptr(io)
      each { |ptr| io.writebytes([ptr.ref_id].pack('L')) }
      each { |ptr| ptr.do_write(io, in_array_ptr: true) }
    end

    def do_read(io)
      if is_array_of_pointers
        super(io, in_array_ptr: true)
        read_ptr(io)
      else
        super
      end
    end

    def read_ptr(io)
      loop do
        element = append_new_element
        element.ref_id = io.readbytes(4).unpack('L').first
        break if eval_parameter(:read_until, { index: self.length - 1 })
      end
      each { |ptr| ptr.do_read(io, in_array_ptr: true) }
    end

    def is_array_of_pointers
      obj_class = @element_prototype.instance_variable_get(:@obj_class)
      obj_class.is_a?(PointerClassPlugin)
    end
  end

  module FixPlugin
    def do_write(io, in_array_ptr: false)
      super(io) unless in_array_ptr
    end

    def do_read(io, in_array_ptr: false)
      super(io) unless in_array_ptr
    end

    def read_ptr(io)
      each { |ptr| ptr.ref_id = io.readbytes(4).unpack('L').first }
      each { |ptr| ptr.do_read(io, in_array_ptr: true) }
    end

    def insert(index, *objs)
      fixed_size = get_parameter(:initial_length)
      if (length + objs.size) != fixed_size
        raise ArgumentError, "Can't add new elements to a FixArray (set to #{fixed_size} elements)"
      else
        super
      end
    end

    def append_new_element
      fixed_size = get_parameter(:initial_length)
      raise ArgumentError, "Can't add new elements to a FixArray (set to #{fixed_size} elements)"
    end
  end

  module ConfClassPlugin; end

  module ConfPlugin
    attr_accessor :max_count_from_read

    def initialize_instance
      @max_count_from_read = 0
      super
    end

    def do_write(io, in_array_ptr: false)
      # Write max_count only if it has not been done already (e.g. structure containing arrays)
      #if io.offset == 0
      unless parent.is_a?(NdrStruct)
        max_count = [length].pack('L')
        io.writebytes(max_count)
      end
      if in_array_ptr
        super(io, in_array_ptr: true) if is_a?(VarPlugin)
      else
        super(io)
      end
    end

    def do_read(io, in_array_ptr: false)
      # Read max_count only if it has not been done already (e.g. structure containing arrays)
      #if io.offset == 0
      unless parent.is_a?(NdrStruct)
        @max_count_from_read = io.readbytes(4).unpack('L').first
      end
      if in_array_ptr
        super(io, in_array_ptr: true) if is_a?(VarPlugin)
      else
        super(io)
      end
    end

    def do_num_bytes
      4 + super
    end
  end

  module VarPlugin
    attr_reader :actual_count_from_read

    def initialize_instance
      @actual_count_from_read = 0
      super
    end

    def do_write(io, in_array_ptr: false)
      offset = 0
      io.writebytes([offset].pack('L'))
      io.writebytes([length].pack('L')) # actual_count
      super(io) unless in_array_ptr
    end

    def do_read(io, in_array_ptr: false)
      io.seekbytes(4)
      @actual_count_from_read = io.readbytes(4).unpack('L').first
      super(io) unless in_array_ptr
    end

    def do_num_bytes
      8 + super
    end
  end

  # [Uni-dimensional Fixed Arrays](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_03_01)
  class FixArray < BinData::Array
    default_parameters initial_length: 0
    def initialize_shared_instance
      super
      extend FixPlugin
      extend ArrayPlugin
    end
  end

  # [Uni-dimensional Conformant Arrays](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_03_02)
  class ConfArray < BinData::Array
    default_parameters(:read_until => lambda { index == (@obj.max_count_from_read - 1) })
    extend ConfClassPlugin

    def initialize_shared_instance
      super
      extend ConfPlugin
      extend ArrayPlugin
    end
  end

  # [Uni-dimensional Varying Arrays](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_03_03)
  class VarArray < BinData::Array
    default_parameters(:read_until => lambda { index == (@obj.actual_count_from_read - 1) })
    def initialize_shared_instance
      super
      extend VarPlugin
      extend ArrayPlugin
    end
  end
  # Uni-dimensional Conformant-varying Arrays
  class ConfVarArray < BinData::Array
    default_parameters(:read_until => lambda { index == (@obj.actual_count_from_read - 1) })
    extend ConfClassPlugin

    def initialize_shared_instance
      super
      extend VarPlugin
      extend ConfPlugin
      extend ArrayPlugin
    end
  end

  # TODO: Multi-dimensional Arrays



  #
  # Strings
  #

  #TODO: review this!!
  module ConfStringPlugin
    attr_accessor :max_count
    def initialize_instance
      @max_count = 1 # NULL terminator
      super
    end

    def do_write(io)
      io.writebytes([@max_count].pack('L'))
      super
    end

    def do_read(io)
      @max_count = io.readbytes(4).unpack('L').first
      super
    end

    def assign(val)
      if val.is_a?(ConfStringPlugin)
        @max_count = val.max_count
      else
        @max_count = val.to_s.length + 1
      end
      super
    end

    def do_num_bytes
      4 + super
    end
  end

  module VarStringPlugin
    def initialize_instance
      @actual_count = 1 # NULL terminator
      super
    end

    def actual_count
      @actual_count
    end

    def do_write(io)
      offset = 0
      io.writebytes([offset].pack('L'))
      io.writebytes([@actual_count].pack('L'))
      super
    end

    def do_read(io)
      io.seekbytes(4)
      @actual_count = io.readbytes(4).unpack('L').first
      super
    end

    def assign(val)
      @actual_count = val.to_s.length + 1
      super
    end

    def do_num_bytes
      8 + super
    end
  end

  # [Varying Strings](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_04_01)
  class VarString < BinData::Stringz
    default_parameters(:max_length => lambda { @obj.actual_count })
    def initialize_shared_instance
      super
      extend VarStringPlugin
    end
  end

  class VarWideString < RubySMB::Field::Stringz16
    default_parameters(:max_length => lambda { @obj.actual_count * 2 })
    def initialize_shared_instance
      super
      extend VarStringPlugin
    end
  end

  # [Conformant and Varying Strings](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_04_02)
  class ConfVarString < BinData::Stringz
    default_parameters(:max_length => lambda { @obj.actual_count })
    def initialize_shared_instance
      super
      extend VarStringPlugin
      extend ConfStringPlugin
    end
  end
  class ConfVarWideString < RubySMB::Field::Stringz16
    default_parameters(:max_length => lambda { @obj.actual_count * 2 })
    def initialize_shared_instance
      super
      extend VarStringPlugin
      extend ConfStringPlugin
    end
  end

  # TODO:[Arrays of Strings](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_05)
  # Microsoft DCERPC uses array of pointers for strings. I couldn't find any reference to array of strings.


  #
  # [Structures](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_06)
  #

  module StructPlugin
    # 1. if there is an array with conformant info in the structure, check if it is the last member
    #   --> if the structure contains a structure with an array, it has to be the last member too
    # 2. if ok, max_count is moved to the beginning
    def do_write(io)
      #if io.offset == 0 && self.class.has_conformant_array
      if self.class.has_conformant_array && !parent.is_a?(NdrStruct)
        max_count = get_max_count
        io.writebytes([max_count].pack('L'))
      end
      super
    end

    def do_read(io)
      #if io.offset == 0 && self.class.has_conformant_array
      if self.class.has_conformant_array && !parent.is_a?(NdrStruct)
        obj = self[field_names.last]
        set_max_count(io.readbytes(4).unpack('L').first)
      end
      super
    end

    def get_max_count
      obj = self[field_names.last]
      return obj.length if obj.class.is_a?(ConfClassPlugin)
      if obj.is_a?(NdrStruct)
        return obj.get_max_count
      end
    end

    def set_max_count(val)
      obj = self[field_names.last]
      if obj.class.is_a?(ConfClassPlugin)
        obj.max_count_from_read = val
      elsif obj.is_a?(NdrStruct)
        obj.set_max_count(val)
      end
    end
  end

  class NdrStruct < BinData::Record
    class << self; attr_reader :has_conformant_array end

    def self.validate_conformant_array(field)
      raise ArgumentError.new(
        "Invalid structure #{self}: Conformant array or embedded structure with Conformant array must be the last member of the structure"
      ) if @has_conformant_array
      obj_class = field.last.prototype.instance_variable_get(:@obj_class)
      @has_conformant_array = true if obj_class.is_a?(ConfClassPlugin)
      @has_conformant_array = true if obj_class < NdrStruct && obj_class.has_conformant_array
    end

    def self.method_missing(symbol, *args, &block)
      field = super
      if field.is_a?(::Array) && field.last.is_a?(BinData::SanitizedField)
        validate_conformant_array(field)
      end
      field
    end

    def initialize_shared_instance
      super
      extend StructPlugin
    end
  end

  # TODO: Unions
  # TODO: Pipes

  #
  # [Pointers](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_10)
  #
  module TopLevelPlugin
    def do_write(io)
      update_ref_ids(self)
      super
    end

    def update_ref_ids(obj, pos = 0)
      case obj
      when BinData::Record
        obj.each_pair do |_name, field|
          pos = update_ref_ids(field, pos)
        end
      when PointerPlugin
        if obj.is_alias?
          ref = obj.get_alias_referent
          raise ArgumentError, "Referent of alias pointer does not exist: #{ref}" if self[ref].nil?
          if self[ref].class != obj.class
            raise ArgumentError, "Pointer points to a different referent type: #{self[ref].class} (set to #{obj.class})"
          end
          obj.ref_id = self[ref].ref_id
        else
          unless obj.ref_id == 0
            obj.ref_id = RubySMB::Dcerpc::Ndr::INITIAL_REF_ID + (pos * 4)
            pos += 1
          end
          return pos
        end
      when ArrayPlugin
        obj.each do |element|
          pos = update_ref_ids(element, pos)
        end
      end
      return pos
    end
  end

  module PointerClassPlugin; end

  INITIAL_REF_ID = 0x00020000

  module PointerPlugin
    attr_accessor :ref_id
    def ref_id=(v)
      @ref_id = v
    end

    def initialize_instance
      extend_top_level_class unless parent.nil?
      @ref_id = 0 if @ref_id.nil?
      super
    end

    def extend_top_level_class
      return if parent.nil?
      current_parent = parent
      loop do
        if current_parent.parent.nil?
          current_parent.extend(TopLevelPlugin) unless current_parent.is_a?(TopLevelPlugin)
          break
        else
          current_parent = current_parent.parent
        end
      end
    end

    def snapshot
      if is_alias?
        parent[get_alias_referent]
      elsif @ref_id == 0
        :null
      else
        super
      end
    end

    def do_write(io, in_array_ptr: false)
      io.writebytes([@ref_id].pack('L')) unless in_array_ptr
      super(io) unless @ref_id == 0 || is_alias?
    end

    def do_read(io, in_array_ptr: false)
      @ref_id = io.readbytes(4).unpack('L').first unless in_array_ptr
      super(io) unless @ref_id == 0 || is_alias?
    end

    def assign(val)
      if val == :null
        @ref_id = 0
      elsif is_alias?
        parent[get_alias_referent].assign(val)
      else
        @ref_id = INITIAL_REF_ID if @ref_id == 0
        super
      end
    end

    def is_alias?
      has_parameter?(:ref_to)
    end

    def get_alias_referent
      get_parameter(:ref_to)
    end

    def do_num_bytes
      return 4 if @ref_id == 0 || is_alias?
      4 + super
    end
  end

  # TODO: define these classes programmatically
  class Uint8Ptr < BinData::Uint8
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end
  class Uint16Ptr < BinData::Uint16le
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end
  class Uint24Ptr < BinData::Uint24le
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end
  class Uint32Ptr < BinData::Uint32le
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end
  class Uint56Ptr < BinData::Uint56le
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end
  class Uint64Ptr < BinData::Uint64le
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end
  class CharPtr < Char
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end
  class BooleanPtr < Boolean
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end

  class StringPtr < ConfVarString
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end

  class WideStringPtr < ConfVarWideString
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end

  class ByteArrayPtr < ConfVarArray
    default_parameter type: :uint8
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end

  class FileTimePtr < RubySMB::Field::FileTime
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end





  # An NDR Context Handle representation as defined in
  # [IDL Data Type Declarations - Basic Type Declarations](http://pubs.opengroup.org/onlinepubs/9629399/apdxn.htm#tagcjh_34_01)
  class NdrContextHandle < BinData::Primitive
    endian :little

    uint32 :context_handle_attributes
    uuid   :context_handle_uuid

    def get
      {:context_handle_attributes => context_handle_attributes, :context_handle_uuid => context_handle_uuid}
    end

    def set(handle)
      if handle.is_a?(Hash)
        self.context_handle_attributes = handle[:context_handle_attributes]
        self.context_handle_uuid = handle[:context_handle_uuid]
      elsif handle.is_a?(NdrContextHandle)
        read(handle.to_binary_s)
      else
        read(handle.to_s)
      end
    end
  end

end

