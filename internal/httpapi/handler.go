package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"log/slog"
	"net/http"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/json-iterator/go/extra"
	"github.com/nsmithuk/local-kms/internal/kms/kmserr"
)

func init() {
	// encodes time.Time as int64 "units since epoch"
	// e.g. time.Second => seconds since epoch
	extra.RegisterTimeAsInt64Codec(time.Second)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		error404(w)
		return
	} else if r.Method != "POST" {
		error405(w)
		return
	} else if !strings.Contains(r.Header.Get("Content-Type"), "json") {
		// Allows both application/x-amz-json-1.1 and application/json
		error415(w)
		return
	}

	_, operation, ok := strings.Cut(r.Header.Get("X-Amz-Target"), ".")
	if !ok {
		error501(w, r)
	}

	slog.Info("Request",
		"operation", operation,
	)

	handler, ok := s.kmsHanders[operation]
	if !ok {
		error501(w, r)
		return
	}

	// Read body
	const maxBody = 1 << 20 // 1 MiB
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		// This is a request problem; in AWS terms you’d usually return InvalidRequestException
		writeAWSJSON11Error(w, http.StatusBadRequest, "InvalidRequestException", "Failed to read request body")
		return
	}
	defer r.Body.Close()

	// Call the dispatched handler
	out, errs := handler(r.Context(), body)
	if errs != nil && len(errs) > 0 {
		// TODO: Look at them all.
		//err := errs[0]

		// We want to log all the errors
		for _, err := range errs {
			slog.Warn(fmt.Sprintf("Response error: %s", err))
		}

		var kerr *kmserr.KMSError

		// If there's a non-validation error, we just emit that.
		for _, err := range errs {
			if !errors.As(err, &kerr) {
				// If we find a non-validation error, we return it.
				writeAWSJSON11Error(w, http.StatusInternalServerError, "InternalFailure", err.Error())
				return
			}
		}

		// Otherwise KMS just return the first error found.
		errors.As(errs[0], &kerr)

		message := kerr.Message.Error()
		if kerr.Type == kmserr.TypeValidation {
			message = "1 validation error detected: " + message
		}

		writeAWSJSON11Error(w, http.StatusBadRequest, string(kerr.Cause), message)
		return
	}

	// Success response: AWS JSON 1.1
	writeAWSJSON11Response(w, out)
}

func writeAWSJSON11Response(w http.ResponseWriter, out any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(http.StatusOK)

	var j = jsoniter.ConfigCompatibleWithStandardLibrary
	_ = j.NewEncoder(w).Encode(out)
}

// 404 isn't a typical KMS operation error, but "NotFoundException" exists and is a reasonable mapping.
func error404(w http.ResponseWriter) {
	writeAWSJSON11Error(w, http.StatusNotFound, "NotFoundException", "Not Found")
}

// 405/415 are “request is invalid” style; KMS commonly uses InvalidRequestException.
func error405(w http.ResponseWriter) {
	writeAWSJSON11Error(w, http.StatusMethodNotAllowed, "InvalidRequestException", "Method Not Allowed")
}

func error415(w http.ResponseWriter) {
	writeAWSJSON11Error(w, http.StatusUnsupportedMediaType, "InvalidRequestException", "Only JSON based content types accepted")
}

// 501: KMS has UnsupportedOperationException.
func error501(w http.ResponseWriter, r *http.Request) {
	writeAWSJSON11Error(
		w,
		http.StatusNotImplemented,
		"UnsupportedOperationException",
		fmt.Sprintf("Passed X-Amz-Target (%s) is not implemented", r.Header.Get("X-Amz-Target")),
	)
}

type responseErr struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
}

func writeAWSJSON11Error(w http.ResponseWriter, status int, errType, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-ErrorType", errType)
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(responseErr{
		Type:    errType,
		Message: message,
	})
}
