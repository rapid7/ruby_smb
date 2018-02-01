module RubySMB
  module Dcerpc

    class NdrSyntax < BinData::Record
      endian :little
      uuid   :if_uuid, initial_value: '8a885d04-1ceb-11c9-9fe8-08002b104860'
      uint16 :if_ver, initial_value: 2
      uint16 :if_ver_minor, initial_value: 0
    end

    class NdrString < BinData::Record
      endian :little

      uint32    :max_count, initial_value: -> { str.length }
      uint32    :offset, initial_value: 0
      uint32    :actual_count, initial_value: -> { str.length }
      stringz16 :str, read_length: -> { actual_count }

      def assign(v)
        self.max_count = v.size
        self.actual_count = v.size
        self.str = v
      end
    end

    class NdrLpStr < BinData::Record
      endian :little

      uint32     :referent_identifier
      ndr_string :ndr_str

      def assign(v)
        self.ndr_str = v
      end

      def to_s
        self.ndr_str.str
      end
    end
  end
end
