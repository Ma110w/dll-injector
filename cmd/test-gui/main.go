package main

import (
	"fmt"
	"image/color"
	"log"
	"runtime"

	"github.com/AllenDang/giu"
)

var (
	testText = "Hello World"
	counter  = 0
)

func loop() {
	counter++

	// Setup fonts on first loop iteration
	if !fontSetupDone {
		setupFonts()
		fontSetupDone = true
	}

	giu.SingleWindow().Layout(
		giu.Column(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 255, A: 255}).To(
				giu.Label("GIU Test Application - Emoji Test"),
			),
			giu.Separator(),
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 0, G: 255, B: 0, A: 255}).To(
				giu.Label("If you can see this, GIU is working correctly!"),
			),
			giu.Spacing(),
			giu.Label(fmt.Sprintf("Counter: %d", counter)),
			giu.Spacing(),

			// Emoji test section
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 0, A: 255}).To(
				giu.Label("Emoji Test:"),
			),
			giu.Label("✅ Success emoji"),
			giu.Label("❌ Error emoji"),
			giu.Label("⚠️ Warning emoji"),
			giu.Label("🚫 Forbidden emoji"),
			giu.Label("🔄 Refresh emoji"),
			giu.Label("☐ Checkbox emoji"),
			giu.Label("🛡️ Shield emoji"),
			giu.Spacing(),

			giu.InputText(&testText).Size(200),
			giu.Spacing(),
			giu.Button("Click Me!").OnClick(func() {
				log.Printf("Test button clicked at iteration %d", counter)
			}),
			giu.Spacing(),
			giu.Button("Exit").OnClick(func() {
				log.Println("Test application exit requested")
				// We'll let the window close naturally
			}),
		),
	)
}

// setupFonts configures font atlas with emoji support
func setupFonts() {
	log.Println("Setting up fonts for emoji support...")

	// Get the default font atlas
	fontAtlas := giu.Context.FontAtlas
	if fontAtlas == nil {
		log.Println("Error: FontAtlas is nil")
		return
	}

	// Pre-register all emoji strings used in the application
	emojiStrings := []string{
		"✅", "❌", "⚠️", "🚫", "🔄", "☐", "🛡️",
	}

	log.Printf("Pre-registering %d emoji strings...", len(emojiStrings))
	for _, emoji := range emojiStrings {
		fontAtlas.RegisterString(emoji)
		log.Printf("Registered: %s", emoji)
	}

	// Try to add Unicode-capable fonts for Windows emoji support
	if runtime.GOOS == "windows" {
		log.Println("Attempting to load Windows Unicode fonts...")
		// List of fonts to try (in order of preference)
		fontCandidates := []string{
			"Segoe UI Emoji",       // Windows 10+ emoji font
			"Segoe UI Symbol",      // Windows 8.1+ symbol font
			"Arial Unicode MS",     // Microsoft Office Unicode font
			"Lucida Sans Unicode",  // Windows Unicode font
			"Tahoma",               // Windows system font with Unicode
			"Microsoft Sans Serif", // Windows system font
		}

		fontLoaded := false
		for _, fontName := range fontCandidates {
			log.Printf("Trying to load font: %s", fontName)
			if font := fontAtlas.AddFont(fontName, 16.0); font != nil {
				log.Printf("Successfully loaded Unicode font: %s", fontName)
				fontLoaded = true
				break
			} else {
				log.Printf("Failed to load font: %s", fontName)
			}
		}

		if !fontLoaded {
			log.Println("Warning: No Unicode fonts found, emojis may display as fallback characters")
		}
	}

	log.Println("Font atlas configured for emoji support")
}

var fontSetupDone = false

func main() {
	log.Println("Starting GIU test application...")

	wnd := giu.NewMasterWindow("GIU Test - Emoji", 500, 400, 0)

	log.Println("Starting main loop...")

	wnd.Run(loop)

	log.Println("Test application finished")
}
