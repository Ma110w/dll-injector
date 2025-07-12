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
	fmt.Printf("Loop iteration: %d\n", counter)
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
				fmt.Println("Button clicked!")
				log.Printf("Button clicked at iteration %d", counter)
			}),
			giu.Spacing(),
			giu.Button("Exit").OnClick(func() {
				fmt.Println("Exit button clicked")
				// We'll let the window close naturally
			}),
		),
	)
}

func main() {
	fmt.Println("Starting GIU test application...")
	log.Println("Creating master window...")

	wnd := giu.NewMasterWindow("GIU Test", 400, 300, 0)
	
	fmt.Println("Master window created, starting loop...")
	log.Println("Starting main loop...")

	wnd.Run(loop)

	fmt.Println("Application finished")
	log.Println("Application finished")
}
