module RubySMB
  module Dcerpc
    module Samr

      # [3.1.5.2.5 SamrEnumerateUsersInDomain (Opnum 13)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/6bdc92c0-c692-4ffb-9de7-65858b68da75)
      class SamrEnumerateUsersInDomainRequest < BinData::Record
        attr_reader :opnum

        endian :little

        sampr_handle         :domain_handle
        ndr_uint32           :enumeration_context
        user_account_control :user_account_control
        ndr_uint32           :prefered_maximum_length

        def initialize_instance
          super
          @opnum = SAMR_ENUMERATE_USERS_IN_DOMAIN
        end
      end

    end
  end
end

