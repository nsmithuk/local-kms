package src

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
	"github.com/NSmithUK/local-kms-go/src/data"
	"github.com/NSmithUK/local-kms-go/src/config"
	"github.com/NSmithUK/local-kms-go/src/handler"
	"strings"
)

var logger = log.New()

func Run() {

	http.HandleFunc("/", handleRequest) // set router
	err := http.ListenAndServe(":9090", nil) // set listen port
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

}

func handleRequest(w http.ResponseWriter, r *http.Request) {

	database := data.NewDatabase(config.DatabasePath)
	defer database.Close()

	//---

	if r.URL.Path != "/" {
		error404(w)

	} else if r.Method != "POST" {
		error405(w)

	} else if !strings.Contains(r.Header.Get("Content-Type"), "json") {
		// Allows both application/x-amz-json-1.1 and application/json
		error415(w)

	} else {

		w.Header().Set("Content-Type", "application/x-amz-json-1.1")

		h := handler.NewRequestHandler(r, logger, database)

		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.ListKeys":
			respond(w, h.ListKeys())

		case "TrentService.CreateKey":
			respond(w, h.CreateKey())

		case "TrentService.CreateAlias":
			respond(w, h.CreateAlias())

		case "TrentService.DeleteAlias":
			respond(w, h.DeleteAlias())

		case "TrentService.ListAliases":
			respond(w, h.ListAliases())

		case "TrentService.ScheduleKeyDeletion":
			respond(w, h.ScheduleKeyDeletion())

		case "TrentService.CancelKeyDeletion":
			respond(w, h.CancelKeyDeletion())

		case "TrentService.DescribeKey":
			respond(w, h.DescribeKey())

		case "TrentService.UpdateAlias":
			respond(w, h.UpdateAlias())

		case "TrentService.UpdateKeyDescription":
			respond(w, h.UpdateKeyDescription())

		case "TrentService.EnableKey":
			respond(w, h.EnableKey())

		case "TrentService.DisableKey":
			respond(w, h.DisableKey())

		case "TrentService.EnableKeyRotation":
			respond(w, h.EnableKeyRotation())

		case "TrentService.GetKeyRotationStatus":
			respond(w, h.GetKeyRotationStatus())

		case "TrentService.DisableKeyRotation":
			respond(w, h.DisableKeyRotation())

		case "TrentService.Encrypt":
			respond(w, h.Encrypt())

		case "TrentService.Decrypt":
			respond(w, h.Decrypt())

		default:
			error501(w)
		}

	}

}

func respond( w http.ResponseWriter, r handler.Response ) {
	w.WriteHeader(r.Code)
	fmt.Fprint(w, r.Body)
}

func error404(w http.ResponseWriter){
	w.WriteHeader(404)
	fmt.Fprint(w, "Page not found")
}

func error405(w http.ResponseWriter){
	w.WriteHeader(405)
	fmt.Fprint(w, "Method Not Allowed")
}

func error415(w http.ResponseWriter){
	w.WriteHeader(415)
	fmt.Fprint(w, "Only JSON based content types accepted")
}

func error501(w http.ResponseWriter){
	w.WriteHeader(501)
	fmt.Fprint(w, "Passed X-Amz-Target is not implemented")
}
