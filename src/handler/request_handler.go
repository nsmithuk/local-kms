package handler

import(
	"net/http"
	log "github.com/sirupsen/logrus"
	"encoding/json"
	"github.com/NSmithUK/local-kms-go/src/data"
)

//-------------------------
// Incoming request

type RequestHandler struct {
	request		*http.Request
	logger 		*log.Logger
	database	*data.Database
}

func NewRequestHandler(r *http.Request, l *log.Logger, d *data.Database) *RequestHandler {
	return &RequestHandler{
		request: r,
		logger: l,
		database: d,
	}
}

/*
	Decodes the request's JSON body into the passed interface
 */
func (r *RequestHandler) decodeBodyInto(v interface{}){
	decoder := json.NewDecoder(r.request.Body)
	decoder.Decode(v)
}

//-------------------------
// Outgoing response

type Response struct {
	Code		int
	Body		string
}

func NewResponse(code int, v interface{}) Response {
	j, err := json.Marshal(v)

	if err != nil {
		return Response{ 500, "Error marshalling JSON"}
	}

	return Response{ code, string(j) }
}
