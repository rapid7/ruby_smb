module RubySMB
  module SMB2
    module Packet


      # An SMB2 RemotedIdentityTreeConnectContext Packet as defined in
      # [2.2.9.2.1 SMB2_REMOTED_IDENTITY_TREE_CONNECT Context](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee7ff411-93e0-484f-9f73-31916fee4cb8)
      # TODO: finish this
      class RemotedIdentityTreeConnectContext < BinData::Record
        endian :little
        uint16 :ticket_type, label: 'Ticket Type', initial_value: 0x0001
        uint16 :ticket_size, label: 'Ticket Size', initial_value: -> { num_bytes }
        uint16 :user, label: 'User'
        uint16 :user_name, label: 'Ticket Type'
        uint16 :domain, label: 'Ticket Type'
        uint16 :groups, label: 'Ticket Type'
        uint16 :restricted_groups, label: 'Ticket Type'
        uint16 :privileges, label: 'Ticket Type'
        uint16 :primary_group, label: 'Ticket Type'
        uint16 :owner, label: 'Ticket Type'
        uint16 :default_dacl, label: 'Ticket Type'
        uint16 :device_groups, label: 'Ticket Type'
        uint16 :user_claims, label: 'Ticket Type'
        uint16 :device_claims, label: 'Ticket Type'
        string :ticket_info, label: 'Ticket Type'
      end

      # An SMB2 TreeConnectContext Packet as defined in
      # [2.2.9.2 SMB2 TREE_CONNECT_CONTEXT Request Values](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/06eaaabc-caca-4776-9daf-82439e90dacd)
      class TreeConnectContext < BinData::Record

        # Context Types

        # This value is reserved.
        SMB2_RESERVED_TREE_CONNECT_CONTEXT_ID = 0x0000
        # The Data field contains remoted identity tree connect context data as specified in section [2.2.9.2.1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee7ff411-93e0-484f-9f73-31916fee4cb8)
        SMB2_REMOTED_IDENTITY_TREE_CONNECT_CONTEXT_ID = 0x0001

        endian :little
        uint16 :context_type, label: 'Context Type'
        uint16 :data_length, label: 'Data Length', initial_value: -> { data.to_binary_s.size }
        uint32 :reserved, label: 'Reserved'
        choice :data, label: 'Data', selection: -> { context_type } do
          remoted_identity_tree_connect_context SMB2_REMOTED_IDENTITY_TREE_CONNECT_CONTEXT_ID, label: 'Remoted Identity Tree Connect Context'
        end

      end

      # An SMB2 TreeConnectRequestExtension Packet as defined in
      # [2.2.9.1 SMB2 TREE_CONNECT Request Extension](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/9ca7328b-b6ca-41a7-9773-0fa237261b76)
      class TreeConnectRequestExtension < BinData::Record
        endian :little
        uint32 :tree_connect_context_offset, label: 'Tree Connect Context Offset', initial_value: -> { tree_connect_contexts.abs_offset }
        uint16 :tree_connect_context_count, label: 'Tree Connect Context Count', initial_value: -> { tree_connect_contexts.size }
        string :reserved, label: 'Reserved', length: 10
        string16 :path, label: 'Path Buffer'
        array :tree_connect_contexts, label: 'Tree Connect Contexts', type: :tree_connect_context, initial_length: -> { tree_connect_context_count }
      end



      # An SMB2 TreeConnectRequest Packet as defined in
      # [2.2.9 SMB2 TREE_CONNECT Request](https://msdn.microsoft.com/en-us/library/cc246567.aspx)
      class TreeConnectRequest < RubySMB::GenericPacket
        COMMAND = RubySMB::SMB2::Commands::TREE_CONNECT

        # Flags (SMB 3.1.1 only)

        # The client has previously connected to the specified cluster share
        # using the SMB dialect of the connection on which the request is received.
        SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT = 0x0001
        # The client can handle synchronous share redirects via a Share Redirect
        # error context response as specified in section [2.2.2.2.2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/f3073a8b-9f0f-47c0-91e5-ec3be9a49f37).
        SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER = 0x0002
        # A tree connect request extension, as specified in section
        # [2.2.9.1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/9ca7328b-b6ca-41a7-9773-0fa237261b76),
        # is present, starting at the Buffer field of this tree connect request.
        SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT = 0x0003

        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size, label: 'Structure Size', initial_value: 9
        # The flags field is only used by SMB 3.1.1, it must be 0 for other versions
        uint16       :flags,          label: 'Flags',          initial_value: 0x00
        uint16       :path_offset,    label: 'Path Offset',    initial_value: 0x48
        uint16       :path_length,    label: 'Path Length',    initial_value: -> { path.to_binary_s.length }
        string16     :path,           label: 'Path Buffer',    onlyif: -> { flags != SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT }
        tree_connect_request_extension :tree_connect_request_extension, label: 'Tree Connect Request Extension', onlyif: -> { flags == SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT }
      end
    end
  end
end
