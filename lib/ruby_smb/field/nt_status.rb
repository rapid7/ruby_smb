require 'windows_error/nt_status'

module RubySMB
  module Field
    # Represents an NTStatus code as defined in
    # [2.3.1 NTSTATUS values](https://msdn.microsoft.com/en-us/library/cc704588.aspx)
    class NtStatus < BinData::Primitive
      endian :little
      uint32 :val

      def get
        val.to_i
      end

      def set(value)
        case value
        when WindowsError::ErrorCode
          set(value.value)
        when Integer
          self.val = value
        else
          self.val = value.to_i
        end
        val
      end

      # Returns a meaningful error code parsed from the numeric value
      #
      # @return [WindowsError::ErrorCode] the ErrorCode object for this code
      def to_nt_status
        WindowsError::NTStatus.find_by_retval(value).first
      end
    end
  end
end
