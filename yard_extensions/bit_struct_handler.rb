class BitStructHandler < YARD::Handlers::Ruby::AttributeHandler
  handles method_call(:unsigned)
  handles method_call(:signed)
  handles method_call(:string)
  namespace_only

  def process
    name      = statement.parameters[0].jump(:tstring_content, :ident).source
    bitlength = statement.parameters[1].jump(:tstring_content, :ident).source

    type = case statement.method_name(true)
           when :unsigned, :signed
             "Fixnum"
           when :string
             "String"
           else
             "Object"
           end

    reader = YARD::CodeObjects::MethodObject.new(namespace, name)
    reader.dynamic = true

    # Grabs the comment and parses it out into MethodObject#docstring
    register(reader)

    if reader.docstring.blank?
      # Use the default if there wasn't a field-specific docstring
      doc = "Value of the `#{name}` field\n"
      reader.docstring.replace(doc)
    end

    # Must have a writer method so this won't show up as read-only, but the
    # reader's stuff takes precedence, so none of its properties seem to
    # matter as long as there is a reader
    writer = reader.dup
    writer.name = "#{name}="

    unless reader.docstring.has_tag?(:return)
      reader.docstring.add_tag(
        YARD::Tags::Tag.new(:return, "#{bitlength}-bit #{statement.method_name(true)} value", type)
      )
    end

    namespace.attributes[scope][name] = SymbolHash[:read => reader, :write => writer]
  end
end

