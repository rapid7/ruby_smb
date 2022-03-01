module RubySMB
  class Server
    # The object representing a single anonymous, guest or authenticated session.
    # @see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ea10b7ae-b053-4e4c-ab31-a48f7d0a79af
    class Session
      # @param [Integer] id This session's unique identifier.
      # @param [String] key This session's key.
      # @param [Symbol] state The state that this session is in.
      # @param user_id The identity of the user associated with this session.
      def initialize(id, key: nil, state: :in_progress, user_id: nil)
        @id = id
        @key = key
        @user_id = user_id
        @state = state
        @signing_required = false
        @metadata = {}
        # tree id => provider processor instance
        @tree_connect_table = {}
        @creation_time = Time.now
      end

      def inspect
        "#<Session id: #{@id.inspect}, user_id: #{@user_id.inspect}, state: #{@state.inspect}>"
      end

      # Whether or not this session is anonymous.
      # @return [Boolean]
      def is_anonymous
        @user_id == Gss::Provider::IDENTITY_ANONYMOUS
      end

      def logoff!
        @tree_connect_table.values.each { |share_processor| share_processor.disconnect! }
        @tree_connect_table.clear
      end

      # This session's unique identifier.
      # @!attribute [rw] id
      #   @return [Integer]
      attr_accessor :id

      # This session's key.
      # @!attribute [rw] key
      #   @return [String]
      attr_accessor :key

      # The identity of the authenticated user.
      # @!attribute [rw] user_id
      attr_accessor :user_id

      # The state that the session is in, (:expired, :in_progress, :valid, etc.).
      # @!attribute [rw] state
      #   @return [Symbol]
      attr_accessor :state

      # Whether or not this session requires messages to be signed.
      # @!attribute [rw] signing_required
      #   @return [Boolean]
      attr_accessor :signing_required

      # The table of tree/share connections in use by this session.
      # @!attribute [rw] tree_connect_table
      #   @return [Hash]
      attr_accessor :tree_connect_table

      # Untyped hash for storing additional arbitrary metadata about the current session
      # @!attribute [rw] metadaa
      #   @return [Hash]
      attr_accessor :metadata

      # The time at which this session was created.
      # @!attribute [r] creation_time
      #   @return [Time]
      attr_reader   :creation_time
    end
  end
end
