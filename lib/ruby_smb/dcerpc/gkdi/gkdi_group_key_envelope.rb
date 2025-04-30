module RubySMB
  module Dcerpc
    module Gkdi

      # [2.2.4 Group Key Envelope](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gkdi/192c061c-e740-4aa0-ab1d-6954fb3e58f7)
      class GkdiGroupKeyEnvelope < BinData::Record
        endian :little

        uint32      :version
        uint8_array :magic, initial_length: 4, initial_value: [ 0x4b, 0x44, 0x53, 0x5b ]
        uint32      :dw_flags
        uint32      :l0_index
        uint32      :l1_index
        uint32      :l2_index
        uuid        :root_key_identifier
        uint32      :cb_kdf_algorithm
        uint32      :cb_kdf_parameters, initial_value: -> { kdf_parameters.length }
        uint32      :cb_secret_agreement_algorithm
        uint32      :cb_secret_agreement_parameters
        uint32      :private_key_length
        uint32      :public_key_length
        uint32      :cb_l1_key
        uint32      :cb_l2_key
        uint32      :cb_domain_name
        uint32      :cb_forest_name
        stringz16   :kdf_algorithm
        struct      :kdf_parameters, only_if: -> { cb_kdf_parameters > 0 } do
          uint8_array :block0, initial_length: 8, initial_value: [ 0, 0, 0, 0, 1, 0, 0, 0 ]
          uint32      :length_of_hash_name, initial_value: -> { hash_algorithm_name.length }
          uint8_array :block1, initial_length: 4, initial_value: [ 0, 0, 0, 0 ]
          stringz16   :hash_algorithm_name
        end
        stringz16   :secret_agreement_algorithm
        uint8_array :secret_agreement_parameters, initial_length: :cb_secret_agreement_parameters
        stringz16   :domain_name
        stringz16   :forest_name
        uint8_array :l1_key, initial_length: 64, only_if: -> { cb_l1_key != 0 }
        uint8_array :l2_key, initial_length: :l2_key_length, only_if: -> { cb_l2_key != 0 }

        private

        def l2_key_length
          return 0 if cb_l2_key == 0
          return 64 if (dw_flags & (1 << 31)) == 0

          public_key_length
        end
      end
    end
  end
end
