package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Tool schemas are the one place that says what a tool accepts. The registry owns
// them, the model runtime compiles them into native provider tools, and the host
// validates every request against the same document before a tool sees it. A tool
// whose schema is missing or malformed is a wiring bug, not a runtime condition.

// ToolDescriptor is the complete public description of one tool.
type ToolDescriptor struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	Version     string          `json:"version"`
}

// toolSchemaDoc is the subset of JSON Schema this project writes and validates:
// an object with typed properties, required names, enums, integer bounds and
// additionalProperties=false. Supporting more would be a schema engine nobody
// needs; supporting less would let the model express arguments the tool cannot
// receive.
type toolSchemaDoc struct {
	Type                 string                        `json:"type"`
	Properties           map[string]toolSchemaProperty `json:"properties"`
	Required             []string                      `json:"required"`
	AdditionalProperties *bool                         `json:"additionalProperties"`
}

type toolSchemaProperty struct {
	Type      string   `json:"type"`
	Enum      []string `json:"enum"`
	Minimum   *int     `json:"minimum"`
	Maximum   *int     `json:"maximum"`
	MaxLength *int     `json:"maxLength"`
}

// ParseToolSchema validates the schema document itself. It is called at
// registration time, so a broken tool cannot start the process.
func ParseToolSchema(raw json.RawMessage) (toolSchemaDoc, error) {
	var document toolSchemaDoc
	if len(bytes.TrimSpace(raw)) == 0 {
		return document, fmt.Errorf("tool schema is empty")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return document, fmt.Errorf("tool schema is not a JSON object: %w", err)
	}
	if document.Type != "object" {
		return document, fmt.Errorf("tool schema type is %q, want object", document.Type)
	}
	if document.AdditionalProperties != nil && *document.AdditionalProperties {
		return document, fmt.Errorf("tool schema must set additionalProperties=false")
	}
	for name, property := range document.Properties {
		switch property.Type {
		case "string", "integer", "boolean":
		default:
			return document, fmt.Errorf("property %q has unsupported type %q", name, property.Type)
		}
		if property.Type == "integer" && property.Enum != nil {
			return document, fmt.Errorf("property %q is an enum over the wrong type", name)
		}
		if property.Minimum != nil && property.Maximum != nil && *property.Minimum > *property.Maximum {
			return document, fmt.Errorf("property %q has minimum above maximum", name)
		}
	}
	for _, required := range document.Required {
		if _, ok := document.Properties[required]; !ok {
			return document, fmt.Errorf("required property %q is not declared", required)
		}
	}
	return document, nil
}

// ValidateToolArgs checks one decoded argument object against the schema. Unknown
// fields are rejected, integers must be JSON integers inside their bounds, and
// strings respect enums and length limits. The check runs before the executor,
// so a tool never has to guess whether its input was well formed.
func ValidateToolArgs(schema json.RawMessage, args json.RawMessage) error {
	document, err := ParseToolSchema(schema)
	if err != nil {
		return err
	}
	raw := bytes.TrimSpace(args)
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&fields); err != nil {
		return fmt.Errorf("%w: arguments must be a JSON object: %v", ErrInvalidArgument, err)
	}
	var unknown []string
	for name := range fields {
		if _, ok := document.Properties[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("%w: unknown argument(s) %s", ErrInvalidArgument, strings.Join(unknown, ", "))
	}
	for _, required := range document.Required {
		if _, ok := fields[required]; !ok {
			return fmt.Errorf("%w: %s is required", ErrInvalidArgument, required)
		}
	}
	for name, property := range document.Properties {
		value, ok := fields[name]
		if !ok {
			continue
		}
		if err := validateToolArgValue(name, property, value); err != nil {
			return err
		}
	}
	return nil
}

func validateToolArgValue(name string, property toolSchemaProperty, raw json.RawMessage) error {
	switch property.Type {
	case "string":
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return fmt.Errorf("%w: %s must be a string", ErrInvalidArgument, name)
		}
		if property.MaxLength != nil && len(text) > *property.MaxLength {
			return fmt.Errorf("%w: %s exceeds %d characters", ErrInvalidArgument, name, *property.MaxLength)
		}
		if len(property.Enum) > 0 {
			for _, allowed := range property.Enum {
				if text == allowed {
					return nil
				}
			}
			return fmt.Errorf("%w: %s=%q is not one of %s", ErrInvalidArgument, name, text, strings.Join(property.Enum, ", "))
		}
	case "integer":
		var value int
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("%w: %s must be an integer", ErrInvalidArgument, name)
		}
		if property.Minimum != nil && value < *property.Minimum {
			return fmt.Errorf("%w: %s is below %d", ErrInvalidArgument, name, *property.Minimum)
		}
		if property.Maximum != nil && value > *property.Maximum {
			return fmt.Errorf("%w: %s is above %d", ErrInvalidArgument, name, *property.Maximum)
		}
	case "boolean":
		var flag bool
		if err := json.Unmarshal(raw, &flag); err != nil {
			return fmt.Errorf("%w: %s must be a boolean", ErrInvalidArgument, name)
		}
	}
	return nil
}

// LegacyToolArgs converts the protocol-v1 argument map, whose values are all
// strings, into the native JSON object described by the schema. Only properties
// the schema declares are converted; scope fields the runtime used to send (such
// as snapshot_id) are dropped, because the host injects trusted scope now. A value
// that does not convert to its declared type is still rejected — compatibility
// must not turn "limit":"ten" into a silent default.
func LegacyToolArgs(schema json.RawMessage, legacy map[string]string) (json.RawMessage, error) {
	document, err := ParseToolSchema(schema)
	if err != nil {
		return nil, err
	}
	fields := make(map[string]any, len(legacy))
	for name, property := range document.Properties {
		text, ok := legacy[name]
		if !ok {
			continue
		}
		switch property.Type {
		case "string":
			fields[name] = text
		case "integer":
			value, err := strconv.Atoi(strings.TrimSpace(text))
			if err != nil {
				return nil, fmt.Errorf("%w: %s must be an integer, got %q", ErrInvalidArgument, name, text)
			}
			fields[name] = value
		case "boolean":
			value, err := strconv.ParseBool(strings.TrimSpace(text))
			if err != nil {
				return nil, fmt.Errorf("%w: %s must be a boolean, got %q", ErrInvalidArgument, name, text)
			}
			fields[name] = value
		default:
			return nil, fmt.Errorf("%w: %s has unsupported schema type %q", ErrInvalidArgument, name, property.Type)
		}
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	if err := ValidateToolArgs(schema, encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

// ToolArgString reads one declared string argument.
func ToolArgString(args json.RawMessage, key string) (string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil {
		return "", fmt.Errorf("%w: arguments must be a JSON object", ErrInvalidArgument)
	}
	raw, ok := fields[key]
	if !ok {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%w: %s must be a string", ErrInvalidArgument, key)
	}
	return strings.TrimSpace(value), nil
}

// ToolArgInt reads one declared integer argument; absent means zero.
func ToolArgInt(args json.RawMessage, key string) (int, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil {
		return 0, fmt.Errorf("%w: arguments must be a JSON object", ErrInvalidArgument)
	}
	raw, ok := fields[key]
	if !ok {
		return 0, nil
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, fmt.Errorf("%w: %s must be an integer", ErrInvalidArgument, key)
	}
	return value, nil
}

// ToolArgBool reads one declared boolean argument; absent means false.
func ToolArgBool(args json.RawMessage, key string) (bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil {
		return false, fmt.Errorf("%w: arguments must be a JSON object", ErrInvalidArgument)
	}
	raw, ok := fields[key]
	if !ok {
		return false, nil
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, fmt.Errorf("%w: %s must be a boolean", ErrInvalidArgument, key)
	}
	return value, nil
}

// ToolSchemaDigest names the exact tool contracts one run used. A run that resumes
// under a different schema must not silently reinterpret old tool calls.
func ToolSchemaDigest(descriptors []ToolDescriptor) string {
	sorted := append([]ToolDescriptor(nil), descriptors...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	parts := make([]string, 0, len(sorted))
	for _, descriptor := range sorted {
		parts = append(parts, descriptor.Name+"@"+descriptor.Version+"\x00"+string(descriptor.InputSchema))
	}
	return digest16(append([]string{"codexploit/tool-schema/v1"}, parts...)...)
}

// ToolArgIntMaybe reads one declared integer argument and reports whether it was
// present, which distinguishes an explicit zero from an omitted field.
func ToolArgIntMaybe(args json.RawMessage, key string) (int, bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil {
		return 0, false, fmt.Errorf("%w: arguments must be a JSON object", ErrInvalidArgument)
	}
	raw, ok := fields[key]
	if !ok {
		return 0, false, nil
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, false, fmt.Errorf("%w: %s must be an integer", ErrInvalidArgument, key)
	}
	return value, true, nil
}
