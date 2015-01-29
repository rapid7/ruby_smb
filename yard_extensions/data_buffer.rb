class DataBufferHandler < YARD::Handlers::Ruby::AttributeHandler
  handles method_call(:data_buffer)
  namespace_only

  def process
    name = statement.parameters[0].jump(:symbol, :ident).source
    name.sub!(":", "")
    if statement.parameters[1]
      bitlength = statement.parameters[1].jump(:tstring_content, :ident).source
    else
      bitlength = 16
    end

    reader = YARD::CodeObjects::MethodObject.new(namespace, name)
    reader.dynamic = true

    # Grabs the comment and parses it out into MethodObject#docstring
    register(reader)

    if reader.docstring.blank?
      # Use the default if there wasn't a field-specific docstring
      doc = "Value of the `#{name}` field\n@note Copy semantics\n@return [String]"
      reader.docstring.replace(doc)
    end

    writer = reader.dup
    writer.name = "#{name}="
    register(writer)
    namespace.attributes[scope][name] = SymbolHash[:read => reader, :write => writer]

    unless reader.docstring.has_tag?(:return)
      reader.docstring.add_tag(
        YARD::Tags::Tag.new(:return, "value", "String")
      )
    end

    reader = YARD::CodeObjects::MethodObject.new(namespace, "#{name}_length")
    reader.dynamic = true

    writer = reader.dup
    writer.name = "#{name}_length="

    reader.docstring.add_tag(
      YARD::Tags::Tag.new(:return, "#{bitlength}-bit length of {##{name}}", "Fixnum")
    )

    namespace.attributes[scope]["#{name}_length"] = SymbolHash[:read => reader, :write => writer]

    reader = YARD::CodeObjects::MethodObject.new(namespace, "#{name}_offset")
    reader.dynamic = true

    writer = reader.dup
    writer.name = "#{name}_offset="

    reader.docstring.add_tag(
      YARD::Tags::Tag.new(:return, "16-bit offset of {##{name}}", "Fixnum")
    )

    namespace.attributes[scope]["#{name}_offset"] = SymbolHash[:read => reader, :write => writer]
  end
end


