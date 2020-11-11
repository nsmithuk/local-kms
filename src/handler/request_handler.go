package handler

import (
	"encoding/json"
	"github.com/nsmithuk/local-kms/src/data"
	log "github.com/sirupsen/logrus"
	"net/http"
)

//--------------------------------------------------------------------
// Incoming request

type RequestHandler struct {
	request  *http.Request
	logger   *log.Logger
	database *data.Database
}

func NewRequestHandler(r *http.Request, l *log.Logger, d *data.Database) *RequestHandler {
	return &RequestHandler{
		request:  r,
		logger:   l,
		database: d,
	}
}

/*
	Decodes the request's JSON body into the passed interface
*/
func (r *RequestHandler) decodeBodyInto(v interface{}) error {
	decoder := json.NewDecoder(r.request.Body)
	return decoder.Decode(v)
}

//--------------------------------------------------------------------
// Outgoing response

type Response struct {
	Code int
	Body string
}

func (r Response) Empty() bool {
	return r.Code == 0 && r.Body == ""
}

func NewResponse(code int, v interface{}) Response {
	if v == nil {
		return Response{code, ""}
	}

	j, err := json.Marshal(v)

	if err != nil {
		return Response{500, "Error marshalling JSON"}
	}

	return Response{code, string(j)}
}

func New400ExceptionResponseFormatted(exception, message string, capitalM bool) Response {
	response := map[string]string{"__type": exception}

	if message != "" {
		if capitalM {
			// In a few cases, AWS KMS responds with a capital 'M' on message.
			response["Message"] = message
		} else {
			response["message"] = message
		}
	}

	return NewResponse(400, response)
}

func New400ExceptionResponse(exception, message string) Response {
	return New400ExceptionResponseFormatted(exception, message, false)
}

//-------------------------------------------------
// Error helpers

func NewDisabledExceptionResponse(message string) Response {
	return New400ExceptionResponse("DisabledException", message)
}

func NewMissingParameterResponse(message string) Response {
	return New400ExceptionResponse("MissingParameterException", message)
}

func NewNotFoundExceptionResponse(message string) Response {
	return New400ExceptionResponse("NotFoundException", message)
}

func NewAlreadyExistsExceptionResponse(message string) Response {
	return New400ExceptionResponse("AlreadyExistsException", message)
}

func NewNotAuthorizedExceptionResponse(message string) Response {
	return New400ExceptionResponse("NotAuthorizedException", message)
}

func NewValidationExceptionResponse(message string) Response {
	return New400ExceptionResponse("ValidationException", message)
}

func NewKMSInvalidStateExceptionResponse(message string) Response {
	return New400ExceptionResponse("KMSInvalidStateException", message)
}

func NewInvalidKeyUsageException(message string) Response {
	return New400ExceptionResponse("InvalidKeyUsageException", message)
}

func NewInvalidCiphertextExceptionResponse(message string) Response {
	return New400ExceptionResponse("InvalidCiphertextException", message)
}

func NewSerializationExceptionResponse(message string) Response {
	return New400ExceptionResponse("SerializationException", message)
}

func NewKMSInvalidSignatureException(message string) Response {
	return New400ExceptionResponse("KMSInvalidSignatureException", message)
}

func NewAccessDeniedExceptionResponse(message string) Response {
	return New400ExceptionResponseFormatted("AccessDeniedException", message, true)
}

func NewUnsupportedOperationException(message string) Response {
	return New400ExceptionResponseFormatted("UnsupportedOperationException", message, true)
}

//---

func NewInternalFailureExceptionResponse(message string) Response {
	return NewResponse(500, map[string]string{
		"__type":  "InternalFailureException",
		"message": message,
	})
}
