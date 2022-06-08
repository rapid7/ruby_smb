module RubySMB::Dcerpc::Ndr

  require 'ruby_smb/field'

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
    def initialize_instance
      @deferred_ptrs = []
      super
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

    def get_top_level_constructed_type
      return self if is_a?(PointerPlugin)

      res = nil
      if parent&.is_a?(ConstructedTypePlugin)
        res = parent.get_top_level_constructed_type
      end
      return res || self
    end

    def do_num_bytes_ptr(struct_offset)
      sum = 0
      @deferred_ptrs.each do |ptr_ref|
        sum += ptr_ref.do_num_bytes(struct_offset + sum, is_deferred: true)
      end
      @deferred_ptrs.clear
      sum
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
        # Set :byte_align to 4 bytes by default, which is the size of the `size
        # information` field (:max_count or :offset/:actual_count). If the
        # elements set with :type are greater, this parameter will be
        # updated later in NdrArrayArgProcessor::sanitize_parameters!
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

    def align_element_size(offset)
      align = eval_parameter(:type).instance_variable_get(:@obj_params)[:byte_align]
      align ? (align - (offset % align)) % align : 0
    end

    def should_process_max_count?
      # :max_count has already been processed if the parent structure is an
      # NdrStruct, but this is not the case if we are dealing with a pointer
      !parent.is_a?(NdrStruct) || self.is_a?(PointerPlugin)
    end

    def do_write(io)
      if is_a?(ConfPlugin) && should_process_max_count?
        io.writebytes([@max_count].pack('L<'))
      end

      if is_a?(VarPlugin)
        io.writebytes([@offset].pack('L<'))
        io.writebytes([@actual_count].pack('L<'))
      end

      unless empty?
        io.writebytes("\x00" * align_element_size(io.offset))
        super
      end

      if has_deferred_ptrs?
        write_ptr(io)
      end
    end

    def has_elements_to_read?
      # When reading a binary stream, the only elements that indicate the array
      # has elements to read are :actual_count, :max_count or :initial_length
      # parameter, depending on the type of NDR Array:
      # 1. When :actual_count is present (NdrVarArray and NdrConfVarArray), it
      #    indicates the actual number of elements passed
      # 2. When only :max_count is present (NdrConfArray), we're assuming the
      #    maximum number of elements is the actual number of elements in this
      #    array
      # 3. None of them are present, but :initial_length parameter has been
      #    set, meaning we are delaing with a fixed array without any embedded
      #    size information (NdrFixArray)
      (@actual_count&.> 0) ||
      @actual_count.nil? && (@max_count&.> 0) ||
      @actual_count.nil? && @max_count.nil? && (eval_parameter(:initial_length)&.> 0)
    end

    def do_read(io)
      if is_a?(ConfPlugin) && should_process_max_count?
        set_max_count(io.readbytes(4).unpack('L<').first)
      end

      if is_a?(VarPlugin)
        @offset = io.readbytes(4).unpack('L<').first
        @actual_count = @read_until_index = io.readbytes(4).unpack('L<').first
      end

      if has_elements_to_read?
        io.seekbytes(align_element_size(io.offset))
        super
      end

      if has_deferred_ptrs?
        read_ptr(io)
      end
    end

    def do_num_bytes(struct_offset = 0)
      sum = 0

      if is_a?(ConfPlugin) && should_process_max_count?
        sum += 4
      end

      if is_a?(VarPlugin)
        sum += 8
      end

      unless empty?
        sum += align_element_size(struct_offset + sum)
        sum += super()
      end

      if has_deferred_ptrs?
        sum += do_num_bytes_ptr(struct_offset + sum)
      end
      sum
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
      @max_count_set = false
      super
    end

    def insert(index, *objs)
      obj = super
      @max_count = length unless @max_count_set
      obj
    end

    def slice_index(index)
      obj = super
      @max_count = length unless @max_count_set
      obj
    end

    def []=(index, value)
      obj = super
      @max_count = length unless @max_count_set
      obj
    end

    def set_max_count(val)
      @max_count = @read_until_index = val
      @max_count_set = true
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
  end

  # This ArgProcessor needs to inherit from BinData::ArrayArgProcessor to make
  # sure the ArrayArgProcessor `sanitize_parameters!` is called. This will
  # perform proper Array-related sanity checks on the given parameters.
  class ::BinData::NdrArrayArgProcessor < BinData::ArrayArgProcessor
    def sanitize_parameters!(obj_class, params)
      res = super

      type_class = params[:type]
      # Let the BinData::Array sanitization routine deal with "no type provided"
      return res unless type_class

      type_class, type_params  = params[:type] if type_class.is_a?(Array)
      if type_class.has_parameter?(:byte_align)
        # According to NDR alignemnt rules for arrays: Array alignment is the
        # largest alignment of the array element type and the size information
        # type, if any.
        # So, here, we pick the greatest value between the size of the `size
        # information` field (:max_count or :offset/:actual_count), which is 4
        # bytes for 32-bit NDR, and the element type size
        byte_align = type_class.instance_variable_get(:@obj_params)[:byte_align]
        if obj_class < NdrFixArray
          # Fixed size arrays doesn't have size information
          params[:byte_align] = byte_align
        else
          params[:byte_align] = [4, byte_align].max
        end
        return res
      elsif type_params&.key?(:byte_align)
        return res
      end

      raise ArgumentError.new(
        "NDR Arrays must only include elements with the `:byte_align` "\
        "parameter set. This makes sure the whole structure is correctly "\
        "aligned. Use a predefined NDR element instead, or provide the "\
        "`:byte_align` parameter in `:type` (Faulty element type: #{params[:type]})"
      )
    end
  end

  # [Uni-dimensional Fixed Arrays](https://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_03_01)
  class NdrFixArray < BinData::Array
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
      if class_name.include?('NdrConfVar')
        target.include ExtendConfStringPlugin
        target.extend ConfClassPlugin
      end
    end
  end

  module ConfStringPlugin
    attr_accessor :max_count

    def initialize_instance
      @max_count = 0
      if has_parameter?(:initial_value)
        set_max_count(get_max_count(eval_parameter(:initial_value)))
      end
      super
    end

    def should_process_max_count?
      # :max_count has already been processed if the parent structure is an
      # NdrStruct, but this is not the case if we are dealing with a pointer
      !parent.is_a?(NdrStruct) || self.is_a?(PointerPlugin)
    end

    def do_write(io)
      if should_process_max_count?
        io.writebytes([@max_count].pack('L<'))
      end
      super
    end

    def do_read(io)
      if should_process_max_count?
        set_max_count(io.readbytes(4).unpack('L<').first)
      end
      super
    end

    def assign(val)
      if val.is_a?(ConfStringPlugin)
        @max_count = val.max_count
      else
        set_max_count(get_max_count(val))
      end
      super
    end

    def do_num_bytes
      sum = 0
      if should_process_max_count?
        # add max_count size
        sum += 4
      end
      sum + super
    end

    def get_max_count(val)
      if is_a?(BinData::Stringz)
        max_count = val.to_s.strip.length
        # Only count the terminating NULL byte if the string is not empty
        max_count += 1 if max_count > 0
        return max_count
      else
        return val.to_s.length
      end
    end

    def set_max_count(val)
      @max_count = val
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
      io.writebytes([@offset].pack('L<'))
      io.writebytes([@actual_count].pack('L<'))
      super if @actual_count > 0
    end

    def do_read(io)
      @offset = io.readbytes(4).unpack('L<').first
      @actual_count = io.readbytes(4).unpack('L<').first
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

    def should_process_max_count?
      # According to the NDR defintion for Structures Containing a Conformant
      # Array:
      #
      # "In the NDR representation of a structure that contains a
      # conformant array, the unsigned long integers that give maximum element
      # counts for dimensions of the array are moved to the beginning of the
      # structure, and the array elements appear in place at the end of the
      # structure. If a structure that contains a conformant array itself a
      # member of another structure, the maximum element counts are further
      # moved to the beginning of the containing structure. This construction
      # iterates through all enclosing structures."
      #
      # This only applies if the current object is the top level structure (no
      # parent). Note that if it is a pointer to a structure and the current
      # object is being deferred, :max_count still need to be processed since
      # it had not been moved to the beginning of the parent structure.
      klass = is_a?(PointerPlugin) ? self.class.superclass : self.class
      parent_obj = nil
      # TODO: possible issue: parent can be a BinData::Choice, and won't be
      # detected as a ConstructedTypePlugin, even if the embeding structure is.
      # Check this with a BinData::Choice that points to a structure embedding
      # a conformant structure
      if parent&.is_a?(ConstructedTypePlugin)
        parent_obj = parent.get_top_level_constructed_type
      end
      klass.has_conformant_array && (parent_obj.nil? || parent_obj.is_deferring(self))
    end

    def do_write(io)
      if should_process_max_count?
        max_count = retrieve_max_count
        io.writebytes([max_count].pack('L<')) if max_count

        # Align the structure according to the alignment rules for the structure
        if respond_to?(:referent_bytes_align)
          io.writebytes("\x00" * referent_bytes_align(io.offset))
        elsif has_parameter?(:byte_align)
          io.writebytes("\x00" * bytes_to_align(self, io.offset))
        end
      end

      super

      if has_deferred_ptrs?
        write_ptr(io)
      end
    end

    def do_read(io)
      if should_process_max_count?
        set_max_count(io.readbytes(4).unpack('L<').first)

        # Align the structure according to the alignment rules for the structure
        if respond_to?(:referent_bytes_align)
          io.seekbytes(referent_bytes_align(io.offset))
        elsif has_parameter?(:byte_align)
          io.seekbytes(bytes_to_align(self, io.offset))
        end
      end

      super

      if has_deferred_ptrs?
        read_ptr(io)
      end
    end

    def retrieve_max_count
      obj = self[field_names.last]
      return obj.length if obj.is_a?(ConfPlugin)
      return obj.get_max_count(obj) if obj.is_a?(ConfStringPlugin)
      if obj.is_a?(NdrStruct)
        return obj.retrieve_max_count
      end
    end

    def set_max_count(val)
      obj = self[field_names.last]
      obj.set_max_count(val)
    end

    def do_num_bytes
      sum = 0

      if should_process_max_count?
        # count max_count (4 bytes)
        max_count = retrieve_max_count
        sum += 4 if max_count

        if respond_to?(:referent_bytes_align)
          sum += referent_bytes_align(sum)
        elsif has_parameter?(:byte_align)
          sum += bytes_to_align(self, sum)
        end
      end

      sum += super

      if has_deferred_ptrs?
        sum += do_num_bytes_ptr(sum)
      end

      sum
    end

    def bytes_to_align(obj, rel_offset)
      if obj.is_a?(PointerPlugin)
        # Pointers are always 4-bytes aligned
        return (4 - (rel_offset % 4)) % 4
      end
      if obj.is_a?(ConfPlugin)
        # `max_count` should have been handled at the begining of the structure
        # already. We need to fix `rel_offset` since it includes the
        # `max_count` 4 bytes, plus the possible padding bytes needed to align
        # the structure. This is required because BinData Struct is not
        # aware of `max_count` and considere the first field to be the begining
        # of the structure instead. We have to make sure the alignment is
        # calculated from the begining of the structure.
        align = eval_parameter(:byte_align)
        pad_length = (align - (4 % align)) % align
        rel_offset += (4 + pad_length)

        # We need to handle another corner case, which is a Conformant array
        # (not Varying). The size information (max_count) has been place in
        # from of the structure and no other size information is present before
        # the actual elements of the array. Therefore, the alignment must be
        # done accroding to th rules of the elements. Since a NdrArray has its
        # default :byte_align value set to 4 (:max_count size), we have to make
        # sure the element size is used instead.
        unless obj.is_a?(VarPlugin)
          return obj.align_element_size(rel_offset)
        end
      end
      is_a?(BinData::ByteAlignPlugin) ? super : 0

    end
  end

  class NdrStruct < BinData::Record
    # Caller must specify :byte_align according to the type of the largest element in the structure.
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
      @standalone_ptr = false
    end

    def do_write(io, is_deferred: false)
      # If for whatever reasons, the #pos value has been modified, reset it to
      # make sure the pointer ref_id will start from INITIAL_REF_ID
      self.class.reset_pos if is_top_level_ptr || @standalone_ptr
      if is_deferred
        super(io, is_deferred: is_deferred)
      else
        super(io)
      end
      # Since #pos has been incremented for each embedded pointer, let's reset
      # it to go back to its initial state
      self.class.reset_pos if is_top_level_ptr || @standalone_ptr
    end

    def to_binary_s
      @standalone_ptr = true
      res = super
      @standalone_ptr = false
      res
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

    def num_bytes
      @standalone_ptr = true
      res = super
      @standalone_ptr = false
      res
    end
  end

  # Windows SMB client uses 0x00020000 as an initial reference ID, but it is
  # rejected by the server on the Windows Server 2003. On this version, only
  # 0x00000001 seems to be accepted. So, we need to use this value to maintain
  # compatibility.
  INITIAL_REF_ID = 0x00000001

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
        fetch_alias_referent
      elsif is_null_ptr? && !eval_parameter(:initial_value)
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

    def write_ref_id(io)
      if is_alias?
        ref_field = fetch_alias_referent
        if ref_field
          if ref_field.class != self.class
            raise ArgumentError, "Pointer points to a different referent type: #{ref_field.class} (set to #{obj.class})"
          end
          @ref_id = ref_field.ref_id
        end
      elsif @ref_id != 0 || (is_null_ptr? && eval_parameter(:initial_value))
        @ref_id = INITIAL_REF_ID + self.class.pos
        self.class.increment_pos unless @standalone_ptr
      end
      io.writebytes([@ref_id].pack('L<'))
    end

    def do_write(io, is_deferred: false)
      if is_deferred
        if is_a?(NdrStruct) && self.class.superclass.has_conformant_array
          # align :max_count since it will be placed in front of the structure.
          # The structure itself will be properly aligned later.
          align = (4 - (io.offset % 4)) % 4
          io.writebytes("\x00" * align)
        else
          io.writebytes("\x00" * referent_bytes_align(io.offset))
        end
      else
        write_ref_id(io)
        parent_obj = nil
        if parent&.is_a?(ConstructedTypePlugin)
          parent_obj = parent.get_top_level_constructed_type
        end
        if parent_obj && @ref_id != 0 && !@standalone_ptr
          parent_obj.defer_ptr(self)
          return
        end
      end
      super(io) unless (is_null_ptr? && !eval_parameter(:initial_value)) || is_alias?
    end

    def do_read(io, is_deferred: false)
      if is_deferred
        if is_a?(NdrStruct) && self.class.superclass.has_conformant_array
          # align :max_count since it will be placed in front of the structure.
          # The structure itself will be properly aligned later.
          align = (4 - (io.offset % 4)) % 4
          io.seekbytes(align)
        else
          io.seekbytes(referent_bytes_align(io.offset))
        end
      else
        @ref_id = io.readbytes(4).unpack('L<').first
        parent_obj = nil
        if parent&.is_a?(ConstructedTypePlugin)
          parent_obj = parent.get_top_level_constructed_type
        end
        if parent_obj && @ref_id != 0
          parent_obj.defer_ptr(self)
          return
        end
      end
      super(io) unless is_null_ptr? || is_alias?
    end

    def assign(val)
      if val == :null
        @ref_id = 0
      elsif is_alias?
        ref_field = fetch_alias_referent
        raise ArgumentError, "Referent of alias pointer does not exist: #{get_parameter(:ref_to)}" unless ref_field
        ref_field.assign(val)
      else
        instantiate_referent if is_null_ptr?
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

    def do_num_bytes(struct_offset = 0, is_deferred: false)
      sum = 0
      if is_deferred
        if is_a?(NdrStruct) && self.class.superclass.has_conformant_array
          # align :max_count since it will be placed in front of the structure.
          # The structure itself will be properly aligned later.
          align = (4 - (struct_offset % 4)) % 4
          sum += align
        else
          sum += referent_bytes_align(struct_offset)
        end
      else
        # add ref_id size
        sum += 4

        parent_obj = nil
        if parent&.is_a?(ConstructedTypePlugin)
          parent_obj = parent.get_top_level_constructed_type
        end
        if parent_obj && @ref_id != 0 && !@standalone_ptr
          parent_obj.defer_ptr(self)
          # only return ref_id size, the actual referent size will be added later
          return sum
        end
      end
      unless (is_null_ptr? && !eval_parameter(:initial_value)) || is_alias?
        if is_a?(ArrayPlugin)
          sum += super(struct_offset + sum)
        else
          sum += super()
        end
      end

      sum
    end

    def instantiate_referent
      @ref_id = INITIAL_REF_ID
    end

    def is_null_ptr?
      @ref_id == 0
    end

    def insert(index, *objs)
      obj = super
      # If we just pushed a new element and it was a null pointer (ref_id==0),
      # we will initialize the ref_id to make sure it is not considered a null
      # pointer anymore
      if is_null_ptr? && is_a?(BinData::Array) && !empty?
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
      new_klass = Class.new(const_get(klass)) do
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

