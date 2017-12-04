module RubySMB
  module Dcerpc

    #https://msdn.microsoft.com/en-us/library/windows/desktop/aa379358(v=vs.85).aspx
    class Uuid < BinData::Primitive
      uint32le :time_low
      uint16le :time_mid
      uint16le :time_hi_and_version

      uint16be :clock_seq_hi_and_res
      uint48be :node

      def get
        self.to_binary_s
      end

      def set(uuid_string)
        components = uuid_string.split('-')
        self.time_low = components[0].hex
        self.time_mid = components[1].hex
        self.time_hi_and_version = components[2].hex
        self.clock_seq_hi_and_res = components[3].hex
        self.node = components[4].hex
      end
    end

  end
end