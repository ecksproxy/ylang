package api

// HTTPError is custom HTTP error for API
type HTTPError struct {
	Message string `json:"message"`
	Detail  string `json:"detail"`
}

func (e *HTTPError) Error() string {
	return e.Message
}

func newError(msg, detail string) *HTTPError {
	return &HTTPError{Message: msg, Detail: detail}
}
