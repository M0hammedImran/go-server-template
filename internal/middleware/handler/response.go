package handler

import "net/http"

type Response struct {
	StatusCode int
	Data       interface{}
	Err        error
}

type SuccessResponse struct {
	Data      interface{} `json:"data"`
	Timestamp int64       `json:"timestamp"`
}

func NewSuccessResponse(statusCode int, data interface{}) *Response {
	return &Response{
		StatusCode: statusCode,
		Data:       data,
	}
}

func NewErrorResponse(statusCode int, code ErrorCode, message string, details interface{}) *Response {
	return &Response{
		StatusCode: statusCode,
		Err: &ErrorResponse{
			Code:    code,
			Message: message,
			Errors:  details,
		},
	}
}

func NewInternalErrorResponse(err error) *Response {
	return NewErrorResponse(http.StatusInternalServerError, InternalServerError, "internal server error", err.Error())
}
