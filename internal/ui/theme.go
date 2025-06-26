package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// ModernDarkTheme is a modern dark theme with improved visual hierarchy
type ModernDarkTheme struct{}

// Ensure ModernDarkTheme implements fyne.Theme interface
var _ fyne.Theme = (*ModernDarkTheme)(nil)

// Color constants - VS Code inspired dark theme palette
var (
	// Primary colors - VS Code blue accent
	colorPrimary   = color.NRGBA{R: 0, G: 122, B: 204, A: 255}  // VS Code blue
	colorSecondary = color.NRGBA{R: 14, G: 99, B: 156, A: 255}  // Darker VS Code blue
	colorAccent    = color.NRGBA{R: 75, G: 155, B: 255, A: 255} // Light accent blue

	// Background colors - VS Code dark theme
	colorBackground      = color.NRGBA{R: 30, G: 30, B: 30, A: 255} // VS Code main background
	colorBackgroundDark  = color.NRGBA{R: 25, G: 25, B: 25, A: 255} // VS Code darker background
	colorCardBackground  = color.NRGBA{R: 37, G: 37, B: 38, A: 255} // VS Code panel background
	colorInputBackground = color.NRGBA{R: 60, G: 60, B: 60, A: 255} // VS Code input background

	// Text colors - VS Code text colors
	colorText        = color.NRGBA{R: 204, G: 204, B: 204, A: 255} // VS Code primary text
	colorTextMuted   = color.NRGBA{R: 140, G: 140, B: 140, A: 255} // VS Code muted text
	colorTextInvert  = color.NRGBA{R: 30, G: 30, B: 30, A: 255}    // Inverted text (dark)
	colorPlaceholder = color.NRGBA{R: 117, G: 117, B: 117, A: 255} // VS Code placeholder

	// Status colors - VS Code status colors
	colorSuccess = color.NRGBA{R: 115, G: 201, B: 144, A: 255} // VS Code green
	colorWarning = color.NRGBA{R: 255, G: 205, B: 84, A: 255}  // VS Code yellow
	colorError   = color.NRGBA{R: 244, G: 71, B: 71, A: 255}   // VS Code red
	colorInfo    = color.NRGBA{R: 100, G: 148, B: 237, A: 255} // VS Code info blue

	// Additional VS Code colors
	colorBorder    = color.NRGBA{R: 69, G: 69, B: 69, A: 255} // VS Code border
	colorHover     = color.NRGBA{R: 42, G: 42, B: 42, A: 255} // VS Code hover
	colorSelection = color.NRGBA{R: 0, G: 122, B: 204, A: 60} // VS Code selection
)

// Color returns the theme color for the specified name
func (m ModernDarkTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	// Modern dark theme with improved visual hierarchy
	switch name {
	case theme.ColorNameBackground:
		return colorBackground
	case theme.ColorNameForeground:
		return colorText
	case theme.ColorNamePrimary:
		return colorPrimary
	case theme.ColorNameFocus:
		return colorAccent
	case theme.ColorNameButton:
		return colorCardBackground
	case theme.ColorNameDisabled:
		return colorTextMuted
	case theme.ColorNamePlaceHolder:
		return colorPlaceholder
	case theme.ColorNameScrollBar:
		return colorBorder
	case theme.ColorNameShadow:
		return color.NRGBA{R: 0, G: 0, B: 0, A: 120}
	case theme.ColorNameInputBackground:
		return colorInputBackground
	case theme.ColorNameHover:
		return colorHover
	case theme.ColorNameSelection:
		return colorSelection
	case theme.ColorNameOverlayBackground:
		return color.NRGBA{R: 0, G: 0, B: 0, A: 200}
	case theme.ColorNameError:
		return colorError
	case theme.ColorNameSuccess:
		return colorSuccess
	case theme.ColorNameWarning:
		return colorWarning
	}

	return theme.DefaultTheme().Color(name, variant)
}

// Font returns the font for the specified text style
func (m ModernDarkTheme) Font(style fyne.TextStyle) fyne.Resource {
	// Use default font but we'll control sizing through Size() method
	return theme.DefaultTheme().Font(style)
}

// Icon returns the theme icon for the specified name
func (m ModernDarkTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

// Size returns the theme size for the specified name
func (m ModernDarkTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 6 // Ultra reduced for more compact layout like VS Code
	case theme.SizeNameInnerPadding:
		return 4 // Ultra reduced for tighter spacing
	case theme.SizeNameScrollBar:
		return 10 // VS Code style scrollbar
	case theme.SizeNameScrollBarSmall:
		return 8
	case theme.SizeNameText:
		return 13 // Slightly smaller for more compact feel
	case theme.SizeNameHeadingText:
		return 16 // More compact heading
	case theme.SizeNameSubHeadingText:
		return 14 // Compact sub-heading
	case theme.SizeNameCaptionText:
		return 11 // Smaller caption text
	case theme.SizeNameInputBorder:
		return 1
	case theme.SizeNameInputRadius:
		return 4 // Less rounded for VS Code style
	case theme.SizeNameSeparatorThickness:
		return 1
	case theme.SizeNameInlineIcon:
		return 16 // Smaller icons for compact layout
	}

	return theme.DefaultTheme().Size(name)
}

// NewModernTheme creates a new modern dark theme
func NewModernTheme() fyne.Theme {
	return &ModernDarkTheme{}
}
