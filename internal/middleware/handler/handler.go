package handler

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func HandleRequest(c *gin.Context, f func(c *gin.Context) *Response) {
	ctx := c.Request.Context()
	if _, ok := ctx.Deadline(); !ok {
		handleRequestReal(c, f(c))
		return
	}
	doneChan := make(chan *Response)
	go func() {
		doneChan <- f(c)
	}()
	select {
	case <-ctx.Done():
		// Nothing to do because err handled from timeout middleware
	case res := <-doneChan:
		handleRequestReal(c, res)
	}
}

func handleRequestReal(c *gin.Context, res *Response) {
	if res.Err == nil {
		statusCode := res.StatusCode
		if statusCode == 0 {
			statusCode = http.StatusOK
		}
		if res.Data != nil {
			c.JSON(res.StatusCode, &SuccessResponse{Data: res.Data, Timestamp: time.Now().Unix()})
		} else {
			c.Status(res.StatusCode)
		}
		return
	}

	var err *ErrorResponse
	err, ok := res.Err.(*ErrorResponse)
	if !ok {
		res.StatusCode = http.StatusInternalServerError
		err = &ErrorResponse{Code: InternalServerError, Message: "An error has occurred, please try again later", Timestamp: time.Now().Unix()}
	}
	c.AbortWithStatusJSON(res.StatusCode, err)
}