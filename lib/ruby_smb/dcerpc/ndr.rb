require 'ruby_smb/field'

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
  class NdrBoolean < BinData::Uint32le
    default_parameters byte_align: 4

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
      val = val.snapshot if val.respond_to?(:snapshot)
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
  class NdrChar < BinData::String
    default_parameter(length: 1, byte_align: 1)
  end
  class NdrWideChar < RubySMB::Field::String16
    default_parameter(length: 2, byte_align: 2)
  end

  # An NDR Enum type as defined in
  # [Transfer Syntax NDR - Enumerated Types](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_02_05_01)
  class NdrEnum < BinData::Int16le
    default_parameters byte_align: 2
  end

  # [Integers](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_02_05)
  # This will define the four size Integers accepted by the NDR protocol:
  # - NdrUint8
  # - NdrUint16
  # - NdrUint32
  # - NdrUint64
  {Uint8: 1, Uint16le: 2, Uint32le: 4, Uint64le: 8}.each do |klass, nb_bytes|
    new_klass_name = "Ndr#{klass.to_s.chomp('le')}"
    unless self.const_defined?(new_klass_name)
      new_klass = Class.new(BinData.const_get(klass)) do
        default_parameters byte_align: nb_bytes
      end
      self.const_set(new_klass_name, new_klass)
      BinData::RegisteredClasses.register(new_klass_name, new_klass)
    end
  end

  class NdrFileTime < RubySMB::Field::FileTime
    # Note that the original Microsoft FILETIME structure is composed of two
    # DWORDs, whereas RubySMB implementation uses an Uint64 field. For this
    # reason, the alignement is set to the size of a DWORD (4 bytes) to match
    # Microsoft structures.
    default_parameters byte_align: 4
  end



  #####################################
  #       NDR Constructed Types       #
  #####################################

  module ConstructedTypePlugin
    def set_top_level
      @deferred_ptrs = []
    end

    def is_top_level?
      !@deferred_ptrs.nil?
    end

    def defer_ptr(ref)
      @deferred_ptrs << ref
    end

    def has_deferred_ptrs?
      !!@deferred_ptrs&.any?
    end

    def write_ptr(io)
      @deferred_ptrs.each do |ptr_ref|
        ptr_ref.do_write(io, is_deferred: true)
      end
      @deferred_ptrs.clear
    end

    def read_ptr(io)
      @deferred_ptrs.each do |ptr_ref|
        ptr_ref.do_read(io, is_deferred: true)
      end
      @deferred_ptrs.clear
    end

    def is_deferring(obj)
      @deferred_ptrs.any? { |e| e.equal?(obj) }
    end
  end

  #
  # Arrays
  #

  module ArrayClassPlugin
    module ExtendArrayPlugin
      def initialize_shared_instance
        super
        extend ArrayPlugin
      end
    end
    module ExtendConfPlugin
      def initialize_shared_instance
        super
        extend ConfPlugin
      end
    end
    module ExtendVarPlugin
      def initialize_shared_instance
        super
        extend VarPlugin
      end
    end
    def self.extended(target)
      target.default_parameters(
        :read_until => lambda { index == (@obj.read_until_index - 1) },
        :byte_align => 4
      )
      target.arg_processor :ndr_array
      class_name = target.to_s.split('::').last
      if class_name.include?('NdrVar') || class_name.include?('NdrConfVar')
        target.include ExtendVarPlugin
      end
      if class_name.include?('NdrConf')
        target.include ExtendConfPlugin
        target.extend ConfClassPlugin
      end
      target.include ExtendArrayPlugin
    end
  end

  module ArrayPlugin
    include ConstructedTypePlugin

    def initialize_instance
      set_top_level unless is_top_level?
      super
    end

    def do_write(io)
      super
      if is_top_level? && has_deferred_ptrs?
        write_ptr(io)
      end
    end

    def do_read(io)
      super
      if is_top_level? && has_deferred_ptrs?
        read_ptr(io)
      end
    end

    def sum_num_bytes_below_index(index)
      (0...index).inject(0) do |sum, i|
        nbytes = 0
        if elements[i].has_parameter?(:byte_align) && elements[i].respond_to?(:bytes_to_align)
          nbytes = elements[i].bytes_to_align(elements[i], sum.ceil)
        end
        nbytes += elements[i].do_num_bytes

        if nbytes.is_a?(Integer)
          sum.ceil + nbytes
        else
          sum + nbytes
        end
      end
    end
  end

  module ConfClassPlugin; end

  module ConfPlugin
    attr_accessor :read_until_index, :max_count

    def initialize_instance
      @read_until_index = 0
      @max_count = 0
      super
    end

    def do_write(io)
      if !parent.is_a?(NdrStruct) || self.is_a?(PointerPlugin)
        io.writebytes([@max_count].pack('L'))
      end
      super(io) if is_a?(VarPlugin) || @max_count > 0
    end

    def do_read(io)
      if !parent.is_a?(NdrStruct) || self.is_a?(PointerPlugin)
        set_max_count(io.readbytes(4).unpack('L').first)
      end
      super(io) if is_a?(VarPlugin) || @max_count > 0
    end

    def insert(index, *objs)
      obj = super
      @max_count = length
      obj
    end

    def slice_index(index)
      obj = super
      @max_count = length
      obj
    end

    def []=(index, value)
      obj = super
      @max_count = length
      obj
    end

    def do_num_bytes
      4 + super
    end

    def set_max_count(val)
        @max_count = @read_until_index = val
    end
  end

  module VarPlugin
    attr_accessor :read_until_index, :actual_count, :offset

    def initialize_instance
      @read_until_index = 0
      @actual_count = 0
      @offset = 0
      super
    end

    def do_write(io)
      io.writebytes([@offset].pack('L'))
      io.writebytes([@actual_count].pack('L'))
      super(io) if @actual_count > 0
    end

    def do_read(io)
      @offset = io.readbytes(4).unpack('L').first
      @actual_count = @read_until_index = io.readbytes(4).unpack('L').first
      super(io) if @actual_count > 0
    end

    def insert(index, *objs)
      obj = super
      @actual_count = length
      obj
    end

    def slice_index(index)
      obj = super
      @actual_count = length
      obj
    end

    def []=(index, value)
      obj = super
      @actual_count = length
      obj
    end

    def do_num_bytes
      8 + super
    end
  end

  class ::BinData::NdrArrayArgProcessor < BinData::ArrayArgProcessor
    def sanitize_parameters!(obj_class, params)
      res = super

      type_class = params[:type]
      # Let's BinData::Array sanitization routine deal with "no type provided"
      return res unless type_class

      type_class, type_params  = params[:type] if type_class.is_a?(Array)
      subject = BinData::RegisteredClasses.lookup(type_class) if type_class.is_a?(Symbol)
      byte_align = type_class.has_parameter?(:byte_align)
      byte_align = type_params.key?(:byte_align) unless byte_align || type_params.nil?

      unless byte_align
        raise ArgumentError.new(
          "NDR Arrays must only include elements with the `:byte_align` "\
          "parameter set. This makes sure the whole structure is correctly "\
          "aligned. Use a predefined NDR element instead, or provide the "\
          "`:byte_align` parameter in `:type` (Faulty element type: #{params[:type]})"
        )
      end
      res
    end
  end

  # [Uni-dimensional Fixed Arrays](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_03_01)
  class NdrFixArray < BinData::Array
    mandatory_parameters :initial_length
    arg_processor :ndr_array

    def initialize_shared_instance
      super
      extend ArrayPlugin
    end

    def insert(index, *objs)
      fixed_size = get_parameter(:initial_length)
      if (length + objs.size) != fixed_size
        raise ArgumentError, "Can't add new elements to a NdrFixArray (set to #{fixed_size} elements)"
      else
        super
      end
    end

    def append_new_element
      fixed_size = get_parameter(:initial_length)
      raise ArgumentError, "Can't add new elements to a NdrFixArray (set to #{fixed_size} elements)"
    end
  end

  # Specific implementation for fixed array of bytes, which can be set from an array of unit8 or a string
  class NdrFixedByteArray < NdrFixArray
    default_parameters(type: :ndr_uint8, byte_align: 1)

    def assign(val)
      val = val.bytes if val.is_a?(String)
      super(val.to_ary)
    end
  end

  # [Uni-dimensional Conformant Arrays](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_03_02)
  class NdrConfArray < BinData::Array
    extend ArrayClassPlugin
  end

  # [Uni-dimensional Varying Arrays](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_03_03)
  class NdrVarArray < BinData::Array
    extend ArrayClassPlugin
  end

  # Uni-dimensional Conformant-varying Arrays
  class NdrConfVarArray < BinData::Array
    extend ArrayClassPlugin
  end

  # TODO: Multi-dimensional Arrays



  #
  # Strings
  #

  module StringClassPlugin
    module ExtendVarStringPlugin
      def initialize_shared_instance
        super
        extend VarStringPlugin
      end
    end
    module ExtendConfStringPlugin
      def initialize_shared_instance
        super
        extend ConfStringPlugin
      end
    end
    def self.extended(target)
      target.default_parameters byte_align: 4
      char_size = 1
      char_size = 2 if target < RubySMB::Field::String16 || target < RubySMB::Field::Stringz16
      if target < BinData::Stringz
        target.default_parameters(:max_length => lambda { @obj.actual_count * char_size })
      else
        target.default_parameters(:length => lambda { @obj.actual_count * char_size })
      end
      target.include ExtendVarStringPlugin
      class_name = target.to_s.split('::').last
      target.include ExtendConfStringPlugin if class_name.include?('NdrConfVar')
    end
  end

  module ConfStringPlugin
    attr_accessor :max_count

    def initialize_instance
      @max_count = 0
      if has_parameter?(:initial_value)
        update_max_count(eval_parameter(:initial_value))
      end
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
        update_max_count(val)
      end
      super
    end

    def do_num_bytes
      4 + super
    end

    def update_max_count(val)
      if is_a?(BinData::Stringz)
        @max_count = val.to_s.strip.length
        # Only count the terminating NULL byte if the string is not empty
        @max_count += 1 if @max_count > 0
      else
        @max_count = val.to_s.length
      end
    end
  end

  module VarStringPlugin
    attr_accessor :actual_count, :offset

    def initialize_instance
      @offset = 0
      @actual_count = 0
      if has_parameter?(:initial_value)
        update_actual_count(eval_parameter(:initial_value))
      end
      super
    end

    def do_write(io)
      io.writebytes([@offset].pack('L'))
      io.writebytes([@actual_count].pack('L'))
      super if @actual_count > 0
    end

    def do_read(io)
      @offset = io.readbytes(4).unpack('L').first
      @actual_count = io.readbytes(4).unpack('L').first
      super if @actual_count > 0
    end

    def assign(val)
      update_actual_count(val)
      super
    end

    def do_num_bytes
      @actual_count > 0 ? (8 + super) : 8
    end

    def update_actual_count(val)
      if is_a?(BinData::Stringz)
        @actual_count = val.to_s.strip.length
        # Only count the terminating NULL byte if the string is not empty
        @actual_count += 1 if @actual_count > 0
      else
        @actual_count = val.to_s.length
      end
    end
  end

  # [Varying Strings](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_04_01)
  class NdrVarString < BinData::String
    extend StringClassPlugin
  end

  class NdrVarStringz < BinData::Stringz
    extend StringClassPlugin
  end

  class NdrVarWideString < RubySMB::Field::String16
    extend StringClassPlugin
  end

  class NdrVarWideStringz < RubySMB::Field::Stringz16
    extend StringClassPlugin
  end

  # [Conformant and Varying Strings](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_04_02)
  class NdrConfVarString < BinData::String
    extend StringClassPlugin
  end

  class NdrConfVarStringz < BinData::Stringz
    extend StringClassPlugin
  end

  class NdrConfVarWideString < RubySMB::Field::String16
    extend StringClassPlugin
  end

  class NdrConfVarWideStringz < RubySMB::Field::Stringz16
    extend StringClassPlugin
  end

  # TODO:[Arrays of Strings](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_05)
  # Microsoft DCERPC uses array of pointers for strings. I couldn't find any reference to array of strings.


  #
  # [Structures](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_06)
  #

  module StructPlugin
    include ConstructedTypePlugin

    def initialize_instance
      set_top_level unless is_top_level?
      super
    end

    def parent_constructed_type(obj = self.parent)
      return nil if obj.nil?
      if obj.is_a?(PointerPlugin)
        return obj if obj.is_a?(ConstructedTypePlugin)
        return nil
      end
      if obj.is_a?(ConstructedTypePlugin)
        res = parent_constructed_type(obj.parent)
        return res || obj
      end
      return nil
    end

    def do_write(io)
      if has_parameter?(:byte_align) && respond_to?(:bytes_to_align)
        io.writebytes("\x00" * bytes_to_align(self, io.offset))
      end

      # 1. if there is an array with conformant info in the structure, check if it is the last member
      #   --> if the structure contains a structure with an array, it has to be the last member too
      # 2. if ok, max_count is moved to the beginning
      klass = self.class
      klass = self.class.superclass if is_a?(PointerPlugin)
      parent_obj = parent_constructed_type
      if klass.has_conformant_array && (parent_obj.nil? || parent_obj.is_deferring(self))
        max_count = get_max_count
        io.writebytes([max_count].pack('L')) if max_count
      end

      super

      if is_top_level? && has_deferred_ptrs?
        write_ptr(io)
      end
    end

    def do_read(io)
      klass = self.class
      parent_obj = nil
      klass = self.class.superclass if is_a?(PointerPlugin)
      parent_obj = parent_constructed_type
      if klass.has_conformant_array && (parent_obj.nil? || parent_obj.is_deferring(self))
        # max_count needs to be aligned according to the alignment rules for
        # primitive data types, which is 4 bytes for an uint32
        # TODO: check if it is needed, since it should have been aligned already:
        align = (4 - (io.offset % 4)) % 4
        io.seekbytes(align)
        set_max_count(io.readbytes(4).unpack('L').first)
      end

      # Then, align the structure according to the alignment rules for the structure
      if respond_to?(:referent_bytes_align)
        io.seekbytes(referent_bytes_align(io.offset))
      elsif has_parameter?(:byte_align) && respond_to?(:bytes_to_align)
        io.seekbytes(bytes_to_align(self, io.offset))
      end

      super

      if is_top_level? && has_deferred_ptrs?
        read_ptr(io)
      end
    end

    def get_max_count
      obj = self[field_names.last]
      return obj.length if obj.is_a?(ConfPlugin)
      if obj.is_a?(NdrStruct)
        return obj.get_max_count
      end
    end

    def set_max_count(val)
      obj = self[field_names.last]
      obj.set_max_count(val)
    end
  end

  class NdrStruct < BinData::Record
    # Caller must specify #byte_align according to the type of the largest element in the structure.
    # See https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_02
    #
    # "The alignment of a structure in the octet stream is the largest of the
    # alignments of the fields it contains. These fields may also be
    # constructed types. The same alignment rules apply recursively to nested
    # constructed types."
    mandatory_parameters(:byte_align)

    class << self; attr_reader :has_conformant_array end

    def self.validate_conformant_array(field)
      if @has_conformant_array
        raise ArgumentError.new(
          "Invalid structure #{self}: Conformant array or embedded structure "\
          "with Conformant array must be the last member of the structure"
        )
      end
      obj_proto = field.last.prototype
      obj_class = obj_proto.instance_variable_get(:@obj_class)
      @has_conformant_array = true if obj_class < NdrStruct && obj_class.has_conformant_array
      if obj_class.is_a?(ConfClassPlugin) && !obj_class.is_a?(PointerClassPlugin)
        @has_conformant_array = true
        # Set array byte_align to the element byte_align value
        element_type = obj_proto.instance_variable_get(:@obj_params)[:type]
        element_byte_align = element_type.instance_variable_get(:@obj_params)[:byte_align]
        obj_proto.instance_variable_get(:@obj_params)[:byte_align] = element_byte_align
      end
    end

    def self.method_missing(symbol, *args, &block)
      field = super
      if field.is_a?(::Array) && field.last.is_a?(BinData::SanitizedField)
        unless field.last.has_parameter?(:byte_align) || field.last.instantiate.bit_aligned?
          raise ArgumentError.new(
            "NDR Structures must only include elements with the `:byte_align` "\
            "parameter set. This makes sure the whole structure is correctly "\
            "aligned. Use a predefined NDR element instead, or provide the "\
            "`:byte_align` parameter when defining the structure "\
            "(Faulty element: #{field.last.name})"
          )
        end
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

  module PointerClassPlugin
    module ExtendPointerPlugin
      def initialize_shared_instance
        super
        extend PointerPlugin
      end
    end
    def self.extended(target)
      target.default_parameters byte_align: 4
      target.arg_processor :ndr_pointer
      target.include ExtendPointerPlugin
    end
  end


  module TopLevelPlugin
    module TopLevelClassMethods
      def pos
        @@pos
      end
      def increment_pos
        @@pos += 1
      end
      def reset_pos
        @@pos = 0
      end
    end

    def self.extended(target)
      target.class.extend(TopLevelClassMethods)
      target.class.reset_pos
    end

    def initialize_instance
      super
    end

    def snapshot
      #update_ref_ids
      super
    end

    def do_write(io, is_deferred: false)
      self.class.reset_pos if is_top_level_ptr
      if is_deferred
        super(io, is_deferred: is_deferred)
      else
        super(io)
      end
    end

    def do_num_bytes
      super
    end

    def set_top_level_ptr
      @top_level_ptr = true
      #update_ref_ids
    end
    def unset_top_level_ptr
      @top_level_ptr = false
    end
    def is_top_level_ptr
      !!@top_level_ptr
    end
  end

  # The initial reference ID starts at 0x00020000, which is what Windows appears to do.
  INITIAL_REF_ID = 0x00020000

  module PointerPlugin
    attr_accessor :ref_id

    def initialize_instance
      if @ref_id.nil?
        if eval_parameter(:initial_value)
          instantiate_referent 
        else
          @ref_id = 0
        end
      end
      extend_top_level_class
      # TODO: validate ref_to parameter, if any:
      #  - should point to an existing pointer in the main structure
      #  - cannot be positioned before the pointer it is refering to
      #  - should be the same type than the referent pointer
      super
    end

    def extend_top_level_class
      current = self
      loop do
        current.extend(TopLevelPlugin) unless current.is_a?(TopLevelPlugin)
        if current.parent.nil?
          current.set_top_level_ptr unless current.is_top_level_ptr
          break
        else
          current.unset_top_level_ptr if current.is_top_level_ptr
          current = current.parent
        end
      end
    end

    def snapshot
      if is_alias?
        ref_field = fetch_alias_referent
        raise ArgumentError, "Referent of alias pointer does not exist: #{get_parameter(:ref_to)}" unless ref_field
        ref_field
      elsif @ref_id == 0 && !eval_parameter(:initial_value)
        :null
      else
        super
      end
    end

    def referent_bytes_align(offset)
      align = self.class.superclass.default_parameters[:byte_align]
      align = eval_parameter(:referent_byte_align) unless align
      bytes = (align - (offset % align)) % align
      bytes
    end

    def write_ref_id(io)
      if is_alias?
        ref_field = fetch_alias_referent
        if ref_field
          if ref_field.class != self.class
            raise ArgumentError, "Pointer points to a different referent type: #{ref_field.class} (set to #{obj.class})"
          end
          @ref_id = ref_field.ref_id
        end
      elsif @ref_id != 0 || (@ref_id == 0 && eval_parameter(:initial_value))
        @ref_id = INITIAL_REF_ID + (self.class.pos * 4)
        self.class.increment_pos
      end
      io.writebytes([@ref_id].pack('L'))
    end

    def do_write(io, is_deferred: false)
      if is_deferred
        io.writebytes("\x00" * referent_bytes_align(io.offset))
      else
        write_ref_id(io)
        parent_obj = parent_constructed_type
        if parent_obj && @ref_id != 0
          parent_obj.defer_ptr(self)
          return
        end
      end
      super(io) unless (@ref_id == 0 && !eval_parameter(:initial_value)) || is_alias?
    end

    def parent_constructed_type(obj = self.parent)
      return nil if obj.nil?
      if obj.is_a?(PointerPlugin)
        return obj if obj.is_a?(ConstructedTypePlugin)
        return nil
      end
      if obj.is_a?(ConstructedTypePlugin)
        res = parent_constructed_type(obj.parent)
        return res || obj
      end
      return nil
    end

    def do_read(io, is_deferred: false)
      if is_deferred
        if is_a?(NdrStruct) && self.class.superclass.has_conformant_array
          # align max_count since it will be placed in front of the structure.
          # The structure itself will be properly aligned later.
          align = (4 - (io.offset % 4)) % 4
          io.seekbytes(align)
        else
          io.seekbytes(referent_bytes_align(io.offset))
        end
      else
        @ref_id = io.readbytes(4).unpack('L').first
        parent_obj = parent_constructed_type
        if parent_obj && @ref_id != 0
          parent_obj.defer_ptr(self)
          return
        end
      end
      super(io) unless @ref_id == 0 || is_alias?
    end

    def assign(val)
      if val == :null
        @ref_id = 0
      elsif is_alias?
        ref_field = fetch_alias_referent
        raise ArgumentError, "Referent of alias pointer does not exist: #{get_parameter(:ref_to)}" unless ref_field
        ref_field.assign(val)
      else
        instantiate_referent if @ref_id == 0
        super
      end
    end

    def is_alias?
      has_parameter?(:ref_to)
    end

    def fetch_alias_referent(current: parent, ref: get_parameter(:ref_to), name: nil)
      return if current.nil?
      if current.get_parameter(:ref_to) == ref
        raise ArgumentError.new(
          "Pointer alias refering to #{ref} cannot be found. This referent "\
          "should appears before the alias in the stream"
        )
      end
      return current if name == ref
      res = nil
      case current
      when ArrayPlugin
        current.each do |element|
          res = fetch_alias_referent(current: element, ref: ref, name: name)
          break if res
        end
      when BinData::Record, BinData::Struct
        current.each_pair do |name, field|
          res = fetch_alias_referent(current: field, ref: ref, name: name)
          break if res
        end
      end
      return res
    end

    def do_num_bytes
      return 4 if @ref_id == 0 || is_alias?
      4 + super
    end

    def instantiate_referent
      @ref_id = INITIAL_REF_ID
    end

    def is_null_ptr?
      @ref_id == 0
    end

    def insert(index, *objs)
      obj = super
      if is_a?(BinData::Array) && !empty?
        instantiate_referent
      end
      obj
    end
  end

  class ::BinData::NdrPointerArgProcessor < BinData::BaseArgProcessor
    def sanitize_parameters!(obj_class, params)
      obj_klass = obj_class
      obj_klass = obj_class.superclass if obj_class.superclass.arg_processor == self
      res = obj_class.superclass.arg_processor.sanitize_parameters!(obj_klass, params)

      return res if obj_class.superclass.default_parameters[:byte_align]
      return res if params[:referent_byte_align]

      raise ArgumentError.new(
        "NDR Pointers referent must have `:byte_align` parameter set. This "\
        "makes sure the whole structure is correctly aligned. Use a predefined "\
        "NDR element instead, or provide the `:referent_byte_align` parameter "\
        "when defining the structure (Faulty pointer class: #{obj_class})"
      )
    end

    def extract_args(obj_class, obj_args)
      obj_class = obj_class.superclass if obj_class.superclass.arg_processor == self
      obj_class.superclass.arg_processor.extract_args(obj_class, obj_args)
    end
  end

  # Pointers to NDR integers. This defined four pointers:
  # - NdrUint8Ptr
  # - NdrUint16Ptr
  # - NdrUint32Ptr
  # - NdrUint64Ptr
  {NdrUint8: 1, NdrUint16: 2, NdrUint32: 4, NdrUint64: 8}.each do |klass, align|
    new_klass_name = "#{klass.to_s}Ptr"
    unless self.const_defined?(new_klass_name)
      new_klass = Class.new(RubySMB::Dcerpc::Ndr.const_get(klass)) do
        extend PointerClassPlugin
      end
      self.const_set(new_klass_name, new_klass)
      BinData::RegisteredClasses.register(new_klass_name, new_klass)
    end
  end

  # Pointers to other classes
  class NdrCharPtr < NdrChar
    extend PointerClassPlugin
  end

  class NdrBooleanPtr < NdrBoolean
    extend PointerClassPlugin
  end

  class NdrStringPtr < NdrConfVarString
    extend PointerClassPlugin
  end

  class NdrStringzPtr < NdrConfVarStringz
    extend PointerClassPlugin
  end

  class NdrWideStringPtr < NdrConfVarWideString
    extend PointerClassPlugin
  end

  class NdrWideStringzPtr < NdrConfVarWideStringz
    extend PointerClassPlugin
  end

  class NdrByteArrayPtr < NdrConfVarArray
    default_parameters type: :ndr_uint8
    extend PointerClassPlugin
  end

  class NdrFileTimePtr < NdrFileTime
    extend PointerClassPlugin
  end

  class UuidPtr < RubySMB::Dcerpc::Uuid
    default_parameter referent_byte_align: 4
    extend PointerClassPlugin
  end

  # An NDR Context Handle representation as defined in
  # [IDL Data Type Declarations - Basic Type Declarations](http://pubs.opengroup.org/onlinepubs/9629399/apdxn.htm#tagcjh_34_01)
  class NdrContextHandle < BinData::Primitive
    default_parameters byte_align: 4
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

