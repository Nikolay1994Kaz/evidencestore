//go:build race

package store

// raceBuild — тесты собраны с -race: симуляции идут меньшим числом
// сценариев (детектор гонок замедляет их в разы).
const raceBuild = true
