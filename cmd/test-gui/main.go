package main

import (
	"fmt"
	"image/color"
	"log"

	"github.com/AllenDang/giu"
)

var (
	testText = "Hello World"
	counter  = 0
)

func loop() {
	counter++

	giu.SingleWindow().Layout(
		giu.Column(
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 255, G: 255, B: 255, A: 255}).To(
				giu.Label("GIU Test Application"),
			),
			giu.Separator(),
			giu.Style().SetColor(giu.StyleColorText, color.RGBA{R: 0, G: 255, B: 0, A: 255}).To(
				giu.Label("If you can see this, GIU is working correctly!"),
			),
			giu.Spacing(),
			giu.Label(fmt.Sprintf("Counter: %d", counter)),
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

func main() {
	log.Println("Starting GIU test application...")

	wnd := giu.NewMasterWindow("GIU Test", 400, 300, 0)

	log.Println("Starting main loop...")

	wnd.Run(loop)

	log.Println("Test application finished")
}
