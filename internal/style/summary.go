package style

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type OutputOptions interface {
	InColor() bool
}

func WriteHeader(builder *strings.Builder, title string) {
	var headerStyle = lipgloss.NewStyle().Bold(true)

	builder.WriteString(headerStyle.Render(title))
	builder.WriteString("\n")
}

func WriteErrorMessage(builder *strings.Builder, msg string, options OutputOptions) {

	builder.WriteString(GetErrorMessage(msg, options))
	builder.WriteString("\n")
}

func GetErrorMessage(msg string, options OutputOptions) string {
	var headerStyle = lipgloss.NewStyle().Bold(true)

	if options.InColor() {
		headerStyle = headerStyle.Foreground(lipgloss.Color(ErrorColor))
	}

	return headerStyle.Render(msg)
}

func WriteSummaryField(builder *strings.Builder, name string, value string, options OutputOptions) {
	builder.WriteString(GetSummaryField(name, value, options))
	builder.WriteString("\n")
}

func GetSummaryField(name string, value string, options OutputOptions) string {
	if options.InColor() {
		return lipgloss.NewStyle().Foreground(lipgloss.Color(FieldNameColor)).Render(name) +
			": " +
			lipgloss.NewStyle().Foreground(lipgloss.Color(FieldValueColor)).Render(value)

	}
	return name + ": " + value
}

func GetLabel(label string, options OutputOptions) string {
	if options.InColor() {
		return lipgloss.NewStyle().Foreground(lipgloss.Color(FieldNameColor)).Render(label)
	}
	return label
}
