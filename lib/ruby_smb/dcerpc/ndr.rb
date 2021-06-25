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



  #####################################
  #       NDR Constructed Types       #
  #####################################

  module ConstructedTypePlugin
    def set_top_level
      @deferred_ptrs = []
    end
    def unset_top_level
      @deferred_ptrs = nil
    end
    def is_top_level?
      !@deferred_ptrs.nil?
    end
    def defer_ptr(ref)
      @deferred_ptrs << ref
    end
    def deferred_ptrs
      @deferred_ptrs
    end
    def clear_deferred_ptrs
      @deferred_ptrs.clear
    end
  end

  #
  # Arrays
  #
  module ArrayPlugin
    include ConstructedTypePlugin

    def initialize_instance
      set_top_level unless is_top_level?
      super
    end

    def do_write(io)
      super
      if is_top_level? && !deferred_ptrs.empty?
        write_ptr(io)
      end
    end

    def write_ptr(io)
      deferred_ptrs.each do |ptr_ref|
        ptr_ref.do_write(io, is_deferred: true)
      end
      clear_deferred_ptrs
    end

    def do_read(io)
      super
      if is_top_level? && !deferred_ptrs.empty?
        read_ptr(io)
      end
    end

    def read_ptr(io)
      deferred_ptrs.each do |ptr_ref|
        ptr_ref.do_read(io, is_deferred: true)
      end
      clear_deferred_ptrs
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

  module FixPlugin
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

  module ConfClassPlugin; end

  module ConfPlugin
    attr_accessor :max_count_from_read

    def initialize_instance
      @max_count_from_read = 0
      super
    end

    def do_write(io)
      unless parent.is_a?(NdrStruct) && !self.is_a?(PointerPlugin)
        max_count = [length].pack('L')
        io.writebytes(max_count)
      end
      super(io)
    end

    def do_read(io)
      unless parent.is_a?(NdrStruct) && !self.is_a?(PointerPlugin)
        @max_count_from_read = io.readbytes(4).unpack('L').first
      end
      super(io)
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

    def do_write(io)
      offset = 0
      io.writebytes([offset].pack('L'))
      io.writebytes([length].pack('L')) # actual_count
      super(io)
    end

    def do_read(io)
      io.seekbytes(4)
      @actual_count_from_read = io.readbytes(4).unpack('L').first
      super(io)
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
      extend FixPlugin
      extend ArrayPlugin
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
    default_parameters(
      :read_until => lambda { index == (@obj.max_count_from_read - 1) },
      :byte_align => 4
    )
    arg_processor :ndr_array

    extend ConfClassPlugin

    def initialize_shared_instance
      super
      extend ConfPlugin
      extend ArrayPlugin
    end
  end

  # [Uni-dimensional Varying Arrays](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_03_03)
  class NdrVarArray < BinData::Array
    default_parameters(
      :read_until => lambda { index == (@obj.actual_count_from_read - 1) },
      :byte_align => 4
    )
    arg_processor :ndr_array

    def initialize_shared_instance
      super
      extend VarPlugin
      extend ArrayPlugin
    end
  end
  # Uni-dimensional Conformant-varying Arrays
  class NdrConfVarArray < BinData::Array
    default_parameters(
      :read_until => lambda { index == (@obj.actual_count_from_read - 1) },
      :byte_align => 4
    )
    arg_processor :ndr_array

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

  module ConfStringPlugin
    attr_accessor :max_count

    def initialize_instance
      @max_count = is_a?(BinData::Stringz) ? 1 : 0
      if has_parameter?(:initial_value)
        @max_count += eval_parameter(:initial_value).size
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
        @max_count = val.to_s.length
        @max_count += 1 if is_a?(BinData::Stringz)
      end
      super
    end

    def do_num_bytes
      4 + super
    end
  end

  module VarStringPlugin
    attr_accessor :actual_count

    def initialize_instance
      @actual_count = is_a?(BinData::Stringz) ? 1 : 0
      if has_parameter?(:initial_value)
        @actual_count += eval_parameter(:initial_value).size
      end
      super
    end

    def do_write(io)
      offset = 0
      io.writebytes([offset].pack('L'))
      io.writebytes([@actual_count].pack('L'))
      super
    end

    def do_read(io)
      # offset value is not used
      io.seekbytes(4)
      @actual_count = io.readbytes(4).unpack('L').first
      super
    end

    def assign(val)
      @actual_count = val.to_s.length
      @actual_count += 1 if is_a?(BinData::Stringz)
      super
    end

    def do_num_bytes
      8 + super
    end
  end

  # [Varying Strings](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_04_01)
  class NdrVarString < BinData::String
    default_parameters(
      :length => lambda { @obj.actual_count },
      byte_align: 4
    )
    def initialize_shared_instance
      super
      extend VarStringPlugin
    end
  end

  class NdrVarStringz < BinData::Stringz
    default_parameters(
      :max_length => lambda { @obj.actual_count },
      byte_align: 4
    )
    def initialize_shared_instance
      super
      extend VarStringPlugin
    end
  end

  class NdrVarWideString < RubySMB::Field::String16
    default_parameters(
      :length => lambda { @obj.actual_count * 2 },
      byte_align: 4
    )
    def initialize_shared_instance
      super
      extend VarStringPlugin
    end
  end

  class NdrVarWideStringz < RubySMB::Field::Stringz16
    default_parameters(
      :max_length => lambda { @obj.actual_count * 2 },
      byte_align: 4
    )
    def initialize_shared_instance
      super
      extend VarStringPlugin
    end
  end

  # [Conformant and Varying Strings](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_04_02)
  class NdrConfVarString < BinData::String
    default_parameters(
      :length => lambda { @obj.actual_count },
      byte_align: 4
    )
    def initialize_shared_instance
      super
      extend VarStringPlugin
      extend ConfStringPlugin
    end

    def is_null_terminated?
      self.value[-1] == "\x00"
    end
  end

  class NdrConfVarStringz < BinData::Stringz
    default_parameters(
      :max_length => lambda { @obj.actual_count },
      byte_align: 4
    )
    def initialize_shared_instance
      super
      extend VarStringPlugin
      extend ConfStringPlugin
    end
  end

  class NdrConfVarWideString < RubySMB::Field::String16
    default_parameters(
      :length => lambda { @obj.actual_count * 2 },
      byte_align: 4
    )
    def initialize_shared_instance
      super
      extend VarStringPlugin
      extend ConfStringPlugin
    end

    def is_null_terminated?
      self.value[-1] == "\x00".encode('utf-16le')
    end
  end

  class NdrConfVarWideStringz < RubySMB::Field::Stringz16
    default_parameters(
      :max_length => lambda { @obj.actual_count * 2 },
      :byte_align => 4
    )
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
      if has_parameter?(:byte_align) && respond_to?(:bytes_to_align)
        io.writebytes("\x00" * bytes_to_align(self, io.offset))
      end

      if self.class.has_conformant_array && !parent.is_a?(NdrStruct)
        max_count = get_max_count
        io.writebytes([max_count].pack('L')) if max_count
      end

      super
    end

    def do_read(io)
      if has_parameter?(:byte_align) && respond_to?(:bytes_to_align)
        io.seekbytes(bytes_to_align(self, io.offset))
      end

      if self.class.has_conformant_array && !parent.is_a?(NdrStruct)
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
      obj_class = field.last.prototype.instance_variable_get(:@obj_class)
      @has_conformant_array = true if obj_class.is_a?(ConfClassPlugin) && !obj_class.is_a?(PointerClassPlugin)
      @has_conformant_array = true if obj_class < NdrStruct && obj_class.has_conformant_array
    end

    def self.method_missing(symbol, *args, &block)
      field = super
      if field.is_a?(::Array) && field.last.is_a?(BinData::SanitizedField)
        unless field.last.has_parameter?(:byte_align)
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

  module TopLevelPlugin
    def snapshot
      update_ref_ids
      super
    end

    def do_write(io, is_deferred: false)
      update_ref_ids if is_top_level_ptr
      if is_deferred
        super(io, is_deferred: is_deferred)
      else
        super(io)
      end
    end

    def do_num_bytes
      update_ref_ids if is_top_level_ptr
      super
    end

    def update_ref_ids(obj = self, pos = 0)
      return pos unless obj

      case obj
      when PointerPlugin
        if obj.is_alias?
          ref_field = obj.fetch_alias_referent
          if ref_field
            if ref_field.class != obj.class
              raise ArgumentError, "Pointer points to a different referent type: #{ref_field.class} (set to #{obj.class})"
            end
            obj.ref_id = ref_field.ref_id
          end
        else
          if obj.ref_id != 0 || (obj.ref_id == 0 && obj.eval_parameter(:initial_value))
            obj.ref_id = RubySMB::Dcerpc::Ndr::INITIAL_REF_ID + (pos * 4)
            pos += 1
          end
        end
      when ArrayPlugin
        obj.each do |element|
          pos = update_ref_ids(element, pos)
        end
      when BinData::Record, BinData::Struct
        obj.each_pair do |_name, field|
          pos = update_ref_ids(field, pos)
        end
      when BinData::Choice
        pos = update_ref_ids(obj.send(:current_choice), pos)
      end
      return pos
    end

    def set_top_level_ptr
      @top_level_ptr = true
      update_ref_ids
    end
    def unset_top_level_ptr
      @top_level_ptr = false
    end
    def is_top_level_ptr
      !!@top_level_ptr
    end
  end

  module PointerClassPlugin; end

  # The initial reference ID starts at 0x00020000, which is what Windows appears to do.
  INITIAL_REF_ID = 0x00020000

  module PointerPlugin
    attr_accessor :ref_id

    def initialize_instance
      if @ref_id.nil?
        if eval_parameter(:initial_value)
          @ref_id = INITIAL_REF_ID
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
      (align - (offset % align)) % align
    end

    def do_write(io, is_deferred: false)
      if is_deferred
        io.writebytes("\x00" * referent_bytes_align(io.offset))
      else
        io.writebytes([@ref_id].pack('L'))
        parent_obj = parent_constructed_type
        if parent_obj
          parent_obj.defer_ptr(self)
          return
        end
      end
      super(io) unless (@ref_id == 0 && !eval_parameter(:initial_value)) || is_alias?
    end

    def parent_constructed_type(obj = self.parent)
      return obj if obj.is_a?(ConstructedTypePlugin)
      return nil if obj.nil?
      return parent_constructed_type(obj.parent)
    end

    def do_read(io, is_deferred: false)
      if is_deferred
        io.readbytes(referent_bytes_align(io.offset))
      else
        @ref_id = io.readbytes(4).unpack('L').first
        parent_obj = parent_constructed_type
        if parent_obj
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
        @ref_id = INITIAL_REF_ID if @ref_id == 0
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
  end

  class ::BinData::NdrPointerArgProcessor < BinData::BaseArgProcessor
    def sanitize_parameters!(obj_class, params)
      res = nil
      if obj_class.superclass.respond_to?(:arg_processor)
        res = obj_class.superclass.arg_processor.sanitize_parameters!(obj_class.superclass, params)
      end

      byte_align = false
      if obj_class.superclass.respond_to?(:default_parameters)
        return res if obj_class.superclass.default_parameters[:byte_align]
      end
      return res if params[:referent_byte_align]

      raise ArgumentError.new(
        "NDR Pointers referent must have `:byte_align` parameter set. This "\
        "makes sure the whole structure is correctly aligned. Use a predefined "\
        "NDR element instead, or provide the `:referent_byte_align` parameter "\
        "when defining the structure (Faulty pointer class: #{obj_class})"
      )
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
        default_parameters byte_align: 4
        arg_processor :ndr_pointer
        extend PointerClassPlugin
        def initialize_shared_instance
          super
          extend PointerPlugin
        end
      end
      self.const_set(new_klass_name, new_klass)
      BinData::RegisteredClasses.register(new_klass_name, new_klass)
    end
  end

  # Pointers to other classes
  class NdrCharPtr < NdrChar
    default_parameters byte_align: 4
    arg_processor :ndr_pointer
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end

  class NdrBooleanPtr < NdrBoolean
    default_parameters byte_align: 4
    arg_processor :ndr_pointer
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end

  class NdrStringPtr < NdrConfVarString
    default_parameters byte_align: 4
    arg_processor :ndr_pointer
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end

  class NdrStringzPtr < NdrConfVarStringz
    default_parameters byte_align: 4
    arg_processor :ndr_pointer
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end

  class NdrWideStringPtr < NdrConfVarWideString
    default_parameters byte_align: 4
    arg_processor :ndr_pointer
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end

  class NdrWideStringzPtr < NdrConfVarWideStringz
    default_parameters byte_align: 4
    arg_processor :ndr_pointer
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end

  class NdrByteArrayPtr < NdrConfVarArray
    default_parameters(type: :ndr_uint8, :byte_align => 4)
    arg_processor :ndr_pointer
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
  end

  class NdrFileTimePtr < RubySMB::Field::FileTime
    default_parameters byte_align: 4, referent_byte_align: 8
    arg_processor :ndr_pointer
    extend PointerClassPlugin
    def initialize_shared_instance
      super
      extend PointerPlugin
    end
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

