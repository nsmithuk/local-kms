package src

import (
	"fmt"
	"github.com/nsmithuk/local-kms/src/config"
	"github.com/nsmithuk/local-kms/src/data"
	"github.com/nsmithuk/local-kms/src/handler"
	log "github.com/sirupsen/logrus"
	"net/http"
	"reflect"
	"strings"
)

func Run(port, seedPath string) {

	//-----------
	// DB Setup

	database := data.NewDatabase(config.DatabasePath)
	defer database.Close()

	//-----------
	// Seeding

	seed(seedPath, database)

	//-----------
	// Start

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, database)
	})

	logger.Infof("Data will be stored in %s", config.DatabasePath)
	logger.Infof("Local KMS started on 0.0.0.0:%s", port)

	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

}

func handleRequest(w http.ResponseWriter, r *http.Request, database *data.Database) {
	logger.Debugf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)

	if r.URL.Path != "/" {
		error404(w)

	} else if r.Method != "POST" {
		error405(w)

	} else if !strings.Contains(r.Header.Get("Content-Type"), "json") {
		// Allows both application/x-amz-json-1.1 and application/json
		error415(w)

	} else {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")

		/*
			The target endpoint is specified in the `X-Amz-Target` header.

			The format is:	TrentService.<method>
			For example: 	TrentService.ListKeys
		*/

		target := strings.Split(r.Header.Get("X-Amz-Target"), ".")

		// Ensure we have at least the 2 components we expect.
		if len(target) >= 2 {
			accountId := config.AWSAccountId
			if config.IAM.IsEnabled() {
				identity, err := config.IAM.AuthRequest(r, target[1], "")
				if err != nil {
					error400(w, err)
					return
				}
				accountId = identity.AccountId
			}

			h := handler.NewRequestHandler(r, logger, database, &accountId)
			method := reflect.ValueOf(h).MethodByName(target[1])
			if method.IsValid() {
				result := method.Call([]reflect.Value{})

				if len(result) == 0 {
					logger.Panicf("Missing expected response from reflected method call\n")
				}

				response, ok := result[0].Interface().(handler.Response)

				if !ok {
					logger.Panicf("Unable to assert type of returned response\n")
				}

				respond(w, response)
				return
			}

		}

		// If we couldn't find a valid method matching the request
		error501(w, r)
		return
	}
}

func respond(w http.ResponseWriter, r handler.Response) {
	w.WriteHeader(r.Code)
	fmt.Fprint(w, r.Body)
}

func error400(w http.ResponseWriter, err error) {
	w.WriteHeader(400)
	fmt.Fprint(w, err.Error())
}

func error404(w http.ResponseWriter) {
	w.WriteHeader(404)
	fmt.Fprint(w, "Page not found")
}

func error405(w http.ResponseWriter) {
	w.WriteHeader(405)
	fmt.Fprint(w, "Method Not Allowed")
}

func error415(w http.ResponseWriter) {
	w.WriteHeader(415)
	fmt.Fprint(w, "Only JSON based content types accepted")
}

func error501(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(501)
	fmt.Fprintf(w, "Passed X-Amz-Target (%s) is not implemented", r.Header.Get("X-Amz-Target"))
}
