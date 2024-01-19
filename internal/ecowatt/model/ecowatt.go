package model

import "time"

type EcoWattResponse struct {
	Signals []Signals `json:"signals"`
}
type Values struct {
	Pas    int `json:"pas"`
	Hvalue int `json:"hvalue"`
}
type Signals struct {
	GenerationFichier time.Time `json:"GenerationFichier"`
	Jour              time.Time `json:"jour"`
	Dvalue            int       `json:"dvalue"`
	Message           string    `json:"message"`
	Values            []Values  `json:"values"`
}

// Formatted JSON: https://odre.opendatasoft.com/api/explore/v2.1/catalog/datasets/signal-ecogaz/records?select=gas_day%20as%20date%2C%20color&order_by=gas_day%20DESC&limit=20
