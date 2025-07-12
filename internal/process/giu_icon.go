package process

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
	"
)

// GetProcessIcon 获取进程图标（简化版本）
func GetProcessIcon(executablePath string) image.Image {
	// 暂时返回默认图标，避免复杂的Windows API调用
	return GetDefaultIcon()
}

// GetDefaultIcon 获取默认图标
func GetDefaultIcon() image.Image {
	// 创建一个简单的16x16默认图标
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))

	// 创建一个简单的图标图案
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			// 创建一个简单的渐变效果
			intensity := uint8((x + y) * 8)
			if intensity > 255 {
				intensity = 255
			}

			// 设置蓝色调的图标
			img.Set(x, y, color.RGBA{
				R: intensity / 4,
				G: intensity / 2,
				B: intensity,
				A: 255,
			})
		}
	}

	return img
}

// GetProcessIconResource 获取进程图标资源（用于Fyne UI）
func GetProcessIconResource(proc ProcessEntry) fyne.Resource {
	// 暂时返回默认图标资源
	// 在实际实现中，可以根据进程类型返回不同的图标
	return theme.ComputerIcon()
}

// ClearIconCache 清空图标缓存（简化版本）
func ClearIconCache() {
	// 简化版本，无需实际缓存
}
