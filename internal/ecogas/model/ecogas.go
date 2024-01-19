package model

type EcoGasSignalResponse struct {
	TotalCount int       `json:"total_count"`
	Results    []Results `json:"results"`
}
type Results struct {
	Date  string `json:"date"`
	Color string `json:"color"`
	Index string `json:"index"`
}
