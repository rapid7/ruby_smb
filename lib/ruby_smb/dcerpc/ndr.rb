module RubySMB
  module Dcerpc
    module Ndr

      # NDR Syntax
      UUID = '8a885d04-1ceb-11c9-9fe8-08002b104860'
      VER_MAJOR = 2
      VER_MINOR = 0

      # An NDR Top-level Full Pointers representation as defined in
      # [Transfer Syntax NDR - Top-level Full Pointers](http://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_11_01)
      # This class must be inherited and the subclass must have a #referent protperty
      class NdrTopLevelFullPointer < BinData::Primitive
        endian :little

        uint32 :referent_identifier, initial_value: 0x00020000

        def get
          is_a_null_pointer? ? 0 : self.referent
        end

        def set(v)
          if v.is_a?(Integer) && v == 0
            self.referent_identifier = 0
          else
            self.referent = v
          end
        end

        def is_a_null_pointer?
          self.referent_identifier == 0
        end
      end

      # An NDR Conformant and Varying String representation as defined in
      # [Transfer Syntax NDR - Conformant and Varying Strings](http://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_04_02)
      # The string elements are Stringz16 (unicode)
      class NdrString < BinData::Primitive
        endian :little

        uint32    :max_count
        uint32    :offset,     initial_value: 0
        uint32    :actual_count
        stringz16 :str,        read_length: -> { actual_count }, onlyif: -> { actual_count > 0 }

        def get
          self.actual_count == 0 ? 0 : self.str
        end

        def set(v)
          if v.is_a?(Integer) && v == 0
            self.actual_count = 0
          else
            self.str = v
            self.max_count = self.actual_count = str.to_binary_s.size / 2
          end
        end
      end

      # A pointer to a NdrString structure
      class NdrLpStr < NdrTopLevelFullPointer
        endian :little

        ndr_string :referent, onlyif: -> { !is_a_null_pointer? }

        def to_s
          is_a_null_pointer? ? "\0" : self.referent
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

      # A pointer to a DWORD
      class NdrLpDword < NdrTopLevelFullPointer
        endian :little

        uint32 :referent, onlyif: -> { !is_a_null_pointer? }
      end

      # An NDR Uni-dimensional Conformant-varying Arrays representation as defined in:
      # [Transfer Syntax NDR - NDR Constructed Types](http://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19_03_03_04)
      class NdrLpByte < BinData::Record
        endian :little

        uint32 :referent_identifier, initial_value: 0x00020000
        uint32 :max_count,           initial_value: -> { actual_count }, onlyif: -> { referent_identifier != 0 }
        uint32 :offset,              initial_value: 0,                   onlyif: -> { referent_identifier != 0 }
        uint32 :actual_count,        initial_value: -> { bytes.size },   onlyif: -> { referent_identifier != 0 }
        array  :bytes, :type => :uint8, initial_length: -> { actual_count }, onlyif: -> { referent_identifier != 0 }
      end

      # A pointer to a Windows FILETIME structure
      class NdrLpFileTime < NdrTopLevelFullPointer
        endian :little

        file_time :referent, onlyif: -> { !is_a_null_pointer? }
      end
    end
  end
end
