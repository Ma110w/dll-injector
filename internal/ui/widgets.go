package ui

import (
	"fmt"
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/whispin/dll-injector/internal/process"
)

// Card is a container component with shadow and rounded corners
type Card struct {
	widget.BaseWidget
	Content fyne.CanvasObject
	Color   color.Color
	Shadow  bool
}

// NewCard creates a new card component
func NewCard(content fyne.CanvasObject, shadow bool) *Card {
	card := &Card{
		Content: content,
		Color:   color.NRGBA{R: 37, G: 37, B: 38, A: 255}, // VS Code panel background
		Shadow:  shadow,
	}
	card.ExtendBaseWidget(card)
	return card
}

// CreateRenderer implements widget.Widget interface
func (c *Card) CreateRenderer() fyne.WidgetRenderer {
	background := canvas.NewRectangle(c.Color)
	background.CornerRadius = 4 // VS Code style less rounded corners

	// Add subtle border
	border := canvas.NewRectangle(color.NRGBA{R: 69, G: 69, B: 69, A: 255})
	border.CornerRadius = 4
	border.StrokeWidth = 1
	border.StrokeColor = color.NRGBA{R: 69, G: 69, B: 69, A: 255}

	var objects []fyne.CanvasObject
	if c.Shadow {
		shadow := canvas.NewRectangle(color.NRGBA{R: 0, G: 0, B: 0, A: 60})
		shadow.CornerRadius = 4
		shadow.Move(fyne.NewPos(3, 3))
		objects = []fyne.CanvasObject{shadow, border, background, c.Content}
	} else {
		objects = []fyne.CanvasObject{border, background, c.Content}
	}

	return &cardRenderer{
		card:       c,
		background: background,
		border:     border,
		objects:    objects,
	}
}

// cardRenderer implements fyne.WidgetRenderer interface
type cardRenderer struct {
	card       *Card
	background *canvas.Rectangle
	border     *canvas.Rectangle
	objects    []fyne.CanvasObject
}

func (r *cardRenderer) Destroy() {}

func (r *cardRenderer) Layout(size fyne.Size) {
	padding := float32(8) // Ultra compact padding for VS Code style

	// Background and border fill the entire area
	r.background.Resize(size)
	r.border.Resize(size)

	// Adjust shadow size if present
	if r.card.Shadow {
		shadow := r.objects[0].(*canvas.Rectangle)
		shadow.Resize(size)
	}

	// Content area has padding
	contentSize := fyne.NewSize(size.Width-padding*2, size.Height-padding*2)
	r.card.Content.Resize(contentSize)
	r.card.Content.Move(fyne.NewPos(padding, padding))
}

func (r *cardRenderer) MinSize() fyne.Size {
	padding := float32(16) // 8 on each side for ultra compact spacing
	contentSize := r.card.Content.MinSize()
	return fyne.NewSize(contentSize.Width+padding, contentSize.Height+padding)
}

func (r *cardRenderer) Objects() []fyne.CanvasObject {
	return r.objects
}

func (r *cardRenderer) Refresh() {
	r.background.FillColor = r.card.Color
	canvas.Refresh(r.card)
}

// SectionTitle creates a title with emphasis style
func SectionTitle(text string) *widget.Label {
	title := widget.NewLabel(text)
	title.TextStyle = fyne.TextStyle{Bold: true}
	return title
}

// ProcessListItem creates a process list item
func ProcessListItem(proc process.ProcessEntry, selected bool) fyne.CanvasObject {
	// Get process icon
	icon := widget.NewIcon(process.GetProcessIconResource(proc))

	nameLabel := widget.NewLabel(proc.Name)
	nameLabel.TextStyle = fyne.TextStyle{Bold: true}

	pidLabel := widget.NewLabel(fmt.Sprintf("PID: %d", proc.PID))
	pidLabel.TextStyle = fyne.TextStyle{Monospace: true}

	infoBox := container.NewVBox(
		nameLabel,
		pidLabel,
	)

	content := container.NewBorder(nil, nil, icon, nil, infoBox)

	// Add background color for selected state
	if selected {
		bg := canvas.NewRectangle(color.NRGBA{R: 0, G: 122, B: 204, A: 60}) // VS Code selection background
		bg.CornerRadius = 4
		return container.NewStack(bg, content)
	}

	return content
}

// ActionButton creates a button with an icon
func ActionButton(icon fyne.Resource, text string, action func()) *widget.Button {
	btn := widget.NewButtonWithIcon(text, icon, action)
	btn.Importance = widget.MediumImportance
	return btn
}

// PrimaryButton creates a primary action button
func PrimaryButton(text string, action func()) *widget.Button {
	btn := widget.NewButton(text, action)
	btn.Importance = widget.HighImportance
	return btn
}

// ModernButton creates a modern styled button with enhanced visual feedback
func ModernButton(text string, action func(), buttonType string) *widget.Button {
	btn := widget.NewButton(text, action)

	switch buttonType {
	case "primary":
		btn.Importance = widget.HighImportance
	case "secondary":
		btn.Importance = widget.MediumImportance
	case "danger":
		btn.Importance = widget.WarningImportance
	default:
		btn.Importance = widget.LowImportance
	}

	return btn
}

// ModernIconButton creates a modern styled button with icon
func ModernIconButton(text string, icon fyne.Resource, action func(), buttonType string) *widget.Button {
	btn := widget.NewButtonWithIcon(text, icon, action)

	switch buttonType {
	case "primary":
		btn.Importance = widget.HighImportance
	case "secondary":
		btn.Importance = widget.MediumImportance
	case "danger":
		btn.Importance = widget.WarningImportance
	default:
		btn.Importance = widget.LowImportance
	}

	return btn
}

// SearchField creates a search field
func SearchField(placeholder string, onChange func(string)) *widget.Entry {
	search := widget.NewEntry()
	search.SetPlaceHolder(placeholder)
	search.OnChanged = onChange

	// Return with search icon
	return search
}

// EmptyStateMessage creates an empty state message
func EmptyStateMessage(icon fyne.Resource, message string) fyne.CanvasObject {
	iconWidget := widget.NewIcon(icon)
	iconWidget.SetResource(theme.InfoIcon())

	label := widget.NewLabel(message)
	label.Alignment = fyne.TextAlignCenter

	return container.NewVBox(
		layout.NewSpacer(),
		iconWidget,
		label,
		layout.NewSpacer(),
	)
}

// OptionGroup creates an option group
func OptionGroup(title string, options []string, selected string, onChange func(string)) fyne.CanvasObject {
	titleLabel := SectionTitle(title)

	radio := widget.NewRadioGroup(options, onChange)
	radio.Selected = selected
	radio.Horizontal = false

	return container.NewVBox(
		titleLabel,
		radio,
	)
}

// CheckGroup creates a checkbox group
func CheckGroup(title string, options map[string]func(bool)) fyne.CanvasObject {
	titleLabel := SectionTitle(title)

	checks := container.NewVBox()
	for text, callback := range options {
		check := widget.NewCheck(text, callback)
		checks.Add(check)
	}

	return container.NewVBox(
		titleLabel,
		checks,
	)
}

// ToggleSwitch creates a toggle switch component
func ToggleSwitch(label string, checked bool, onChange func(bool)) fyne.CanvasObject {
	// Use Check component as base, but add label and container to make it look like a switch
	toggle := widget.NewCheck("", onChange)
	toggle.Checked = checked

	// Create label
	textLabel := widget.NewLabel(label)

	// Arrange label and switch horizontally
	return container.NewBorder(nil, nil, textLabel, toggle, layout.NewSpacer())
}

// NewCustomEntry creates an entry with custom background and text colors
func NewCustomEntry(entry *widget.Entry, backgroundColor, textColor color.Color) fyne.CanvasObject {
	// Create background rectangle
	background := canvas.NewRectangle(backgroundColor)

	// Set custom theme with text color
	customTheme := &customEntryTheme{
		baseTheme:    theme.DefaultTheme(),
		textColor:    textColor,
		placeHolder:  textColor,
		primaryColor: textColor,
	}

	// Temporarily swap theme to set text color
	originalTheme := fyne.CurrentApp().Settings().Theme()
	fyne.CurrentApp().Settings().SetTheme(customTheme)

	// Restore after theme change
	defer fyne.CurrentApp().Settings().SetTheme(originalTheme)

	// Refresh entry to apply new colors
	canvas.Refresh(entry)

	// Place entry on top of background
	container := container.NewMax(background, entry)

	return container
}

// customEntryTheme provides a theme with custom colors
type customEntryTheme struct {
	baseTheme    fyne.Theme
	textColor    color.Color
	placeHolder  color.Color
	primaryColor color.Color
}

// Color overrides theme's color method
func (t *customEntryTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameForeground, theme.ColorNamePrimary:
		return t.textColor
	case theme.ColorNamePlaceHolder:
		return t.placeHolder
	case theme.ColorNameBackground:
		return color.Transparent // Make background transparent
	default:
		return t.baseTheme.Color(name, variant)
	}
}

// Font uses base theme's font
func (t *customEntryTheme) Font(style fyne.TextStyle) fyne.Resource {
	return t.baseTheme.Font(style)
}

// Icon uses base theme's icon
func (t *customEntryTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return t.baseTheme.Icon(name)
}

// Size uses base theme's size
func (t *customEntryTheme) Size(name fyne.ThemeSizeName) float32 {
	return t.baseTheme.Size(name)
}

// ConsoleText is a specialized text component for console display with fixed background and text colors
type ConsoleText struct {
	widget.BaseWidget
	Text            string
	BackgroundColor color.Color
	TextColor       color.Color
	TextStyle       fyne.TextStyle
	Wrapping        fyne.TextWrap
}

// NewConsoleText creates a new console text component
func NewConsoleText(backgroundColor, textColor color.Color) *ConsoleText {
	t := &ConsoleText{
		BackgroundColor: backgroundColor,
		TextColor:       textColor,
		TextStyle:       fyne.TextStyle{Monospace: true},
		Wrapping:        fyne.TextWrapWord,
	}
	t.ExtendBaseWidget(t)
	return t
}

// SetText sets the text content to display
func (t *ConsoleText) SetText(text string) {
	t.Text = text
	// Force size recalculation by invalidating the current size
	t.Resize(t.MinSize())
	t.Refresh()
}

// CreateRenderer implements custom rendering
func (t *ConsoleText) CreateRenderer() fyne.WidgetRenderer {
	background := canvas.NewRectangle(t.BackgroundColor)

	// Create a container to hold all text lines
	lineContainer := container.NewVBox()

	return &consoleTextRenderer{
		background:    background,
		lineContainer: lineContainer,
		objects:       []fyne.CanvasObject{background, lineContainer},
		console:       t,
	}
}

// MinSize returns the component's minimum size
func (t *ConsoleText) MinSize() fyne.Size {
	t.ExtendBaseWidget(t)

	// Calculate actual content size based on text lines
	if t.Text == "" {
		return fyne.NewSize(300, 200)
	}

	lines := strings.Split(t.Text, "\n")
	lineHeight := theme.TextSize() + 2                 // Add some padding between lines
	totalHeight := float32(len(lines))*lineHeight + 10 // Add some padding

	// Ensure minimum width
	minWidth := float32(300)

	return fyne.NewSize(minWidth, totalHeight)
}

// Console text renderer
type consoleTextRenderer struct {
	background    *canvas.Rectangle
	lineContainer *fyne.Container
	objects       []fyne.CanvasObject
	console       *ConsoleText
}

// MinSize returns the renderer's minimum size
func (r *consoleTextRenderer) MinSize() fyne.Size {
	// Calculate actual content size based on text lines
	if r.console.Text == "" {
		return fyne.NewSize(300, 200)
	}

	lines := strings.Split(r.console.Text, "\n")
	lineHeight := theme.TextSize() + 2                 // Add some padding between lines
	totalHeight := float32(len(lines))*lineHeight + 10 // Add some padding

	// Ensure minimum width
	minWidth := float32(300)

	return fyne.NewSize(minWidth, totalHeight)
}

// Layout handles layout logic
func (r *consoleTextRenderer) Layout(size fyne.Size) {
	// Background fills the entire area
	r.background.Resize(size)

	// Set line container size with small padding
	padding := float32(5)
	contentSize := fyne.NewSize(size.Width-2*padding, size.Height-2*padding)
	r.lineContainer.Resize(contentSize)
	r.lineContainer.Move(fyne.NewPos(padding, padding))
}

// Objects returns rendered objects
func (r *consoleTextRenderer) Objects() []fyne.CanvasObject {
	return r.objects
}

// Destroy renderer cleanup
func (r *consoleTextRenderer) Destroy() {}

// Refresh refreshes the renderer
func (r *consoleTextRenderer) Refresh() {
	// Clear all current lines
	r.lineContainer.Objects = nil

	// Split text by line
	lines := strings.Split(r.console.Text, "\n")

	// Create text objects for each line
	for _, line := range lines {
		// If line is empty, add a space to maintain line height
		if line == "" {
			line = " " // Use space instead of empty line to maintain line height
		}

		lineText := canvas.NewText(line, r.console.TextColor)
		lineText.TextStyle = r.console.TextStyle
		lineText.TextSize = theme.TextSize() // Use theme-defined text size

		// Wrap each line in a container for proper spacing
		lineBox := container.NewHBox(lineText)
		r.lineContainer.Add(lineBox)
	}

	// Update background color
	r.background.FillColor = r.console.BackgroundColor

	// Refresh all objects
	canvas.Refresh(r.background)
	canvas.Refresh(r.lineContainer)

	// Force layout update to ensure proper sizing for scrolling
	r.lineContainer.Refresh()

	canvas.Refresh(r.console)
}

// ModernGroup creates a VS Code styled group container with title
func ModernGroup(title string, content fyne.CanvasObject) fyne.CanvasObject {
	// Create title with VS Code styling
	titleLabel := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	titleLabel.TextStyle.Bold = true

	// Create a separator line with VS Code color
	separator := canvas.NewRectangle(color.NRGBA{R: 69, G: 69, B: 69, A: 255})
	separator.Resize(fyne.NewSize(0, 1))

	// Create ultra compact spacing container
	spacer := container.NewVBox()
	spacer.Resize(fyne.NewSize(0, 2)) // Ultra reduced spacing

	// Create the group container with minimal padding
	groupContent := container.NewVBox(
		titleLabel,
		spacer,
		separator,
		spacer,
		content, // Remove extra padding for more compact layout
	)

	// Wrap in a card for VS Code appearance
	return NewCard(groupContent, false)
}

// ModernSection creates a compact section with title and content
func ModernSection(title string, content fyne.CanvasObject) fyne.CanvasObject {
	// Create title with VS Code styling
	titleLabel := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	// Add ultra minimal spacing for compact layout
	spacer := container.NewVBox()
	spacer.Resize(fyne.NewSize(0, 2)) // Ultra reduced from 4 to 2

	return container.NewVBox(
		titleLabel,
		spacer,
		content,
	)
}

// CompactButton creates a compact button for VS Code style interface
func CompactButton(text string, action func()) *widget.Button {
	btn := widget.NewButton(text, action)
	btn.Importance = widget.MediumImportance
	return btn
}

// CompactIconButton creates a compact button with icon for VS Code style interface
func CompactIconButton(text string, icon fyne.Resource, action func()) *widget.Button {
	btn := widget.NewButtonWithIcon(text, icon, action)
	btn.Importance = widget.MediumImportance
	return btn
}

// UltraCompactGroup creates an ultra compact group for top sections like DLL and Method
func UltraCompactGroup(title string, content fyne.CanvasObject) fyne.CanvasObject {
	// Create title with VS Code styling
	titleLabel := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	titleLabel.TextStyle.Bold = true

	// Create a separator line with VS Code color
	separator := canvas.NewRectangle(color.NRGBA{R: 69, G: 69, B: 69, A: 255})
	separator.Resize(fyne.NewSize(0, 1))

	// Create minimal spacing container (no spacing between title and separator)
	// Create the group container with ultra minimal padding
	groupContent := container.NewVBox(
		titleLabel,
		separator,
		content, // No spacer between separator and content for ultra compact layout
	)

	// Wrap in a card with ultra compact padding
	return NewCard(groupContent, false)
}

// InlineLabelEntry creates a compact entry with label on the left side
func InlineLabelEntry(labelText string, entry *widget.Entry, button *widget.Button) fyne.CanvasObject {
	// Create label with VS Code styling
	label := widget.NewLabelWithStyle(labelText, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	// Use a grid layout to ensure both entry and button are visible
	// This gives more predictable layout behavior
	return container.NewGridWithColumns(3,
		label,  // Column 1: Label
		entry,  // Column 2: Entry (will take available space)
		button, // Column 3: Button (fixed size)
	)
}

// InlineLabelRadioGroup creates a compact radio group with label on the left side
func InlineLabelRadioGroup(labelText string, radioGroup *widget.RadioGroup) fyne.CanvasObject {
	// Create label with VS Code styling
	label := widget.NewLabelWithStyle(labelText, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	// Use border layout to position label on left and radio group on right
	return container.NewBorder(
		nil, nil,
		label,
		nil,
		radioGroup,
	)
}

// InlineLabelButton creates a compact button with label on the left side and additional info
func InlineLabelButton(labelText string, button *widget.Button, infoLabel *widget.Label) fyne.CanvasObject {
	// Create label with VS Code styling
	label := widget.NewLabelWithStyle(labelText, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	// Create container for info label and button (button after info label)
	buttonContainer := container.NewHBox(infoLabel, button)

	// Use border layout to position label on left and button container on right
	return container.NewBorder(
		nil, nil,
		label,
		nil,
		buttonContainer,
	)
}
