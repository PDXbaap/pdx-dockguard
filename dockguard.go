// Copyright 2018 The PDX Blockchain Hybercloud Authors
// This file is part of the PDX chainmux implementation.
//
// The PDX Blcockchain Hypercloud is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The PDX Blockchain Hypercloud is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the software. If not, see <http://www.gnu.org/licenses/>.


// PDX sandbox, a setgid docker helper for PDX smart-contract sandboxing.

package main

import (
	"fmt"
	"log"
	"strings"
	"net/http"
	"net"
	"io/ioutil"
)

func handler(w http.ResponseWriter, r *http.Request) {

	var cmd string

	if r.Method == http.MethodGet {
		cmd = r.URL.Query().Get("cmd")
	} else if r.Method == http.MethodPost {
		body, err := ioutil.ReadAll(r.Body)
		defer r.Body.Close()
		if err != nil {
			log.Println("invalid request")
			http.Error(w, "invalid request", http.StatusUnauthorized)
			return
		}
		cmd = string(body)
	} else {
		log.Println("unsupported http method: ", r.Method)
		http.Error(w, "unsupported http method: " + r.Method, http.StatusUnauthorized)
		return
	}

	log.Println("received cmd: " + cmd)

	args := strings.Fields(cmd)

	ok, reason, name := accessControl(args);

	if !ok {
		log.Println("unauthorized:", reason)
		http.Error(w, "unauthorized: " + reason, http.StatusUnauthorized)
		return
	}

	if name == "" {
		log.Println("missing container name, noop")
		http.Error(w, "missing container name", http.StatusBadRequest)
		return
	}

	saveStartedContainers(name)

	log.Println("starting container: ", name)

	exitcode, output := execute(args)

	w.Header().Set("DOCKER_EXIT_CODE", exitcode)

	if exitcode != "0" {
		http.Error(w, output, http.StatusBadRequest)
	} else {
		log.Println("started container:", name)
		fmt.Println(w, output)
	}

	return
}

func main() {

	lock()

	defer unlock()

	listener, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("listening on: %s", listener.Addr().String())

	save(listener.Addr().String())

	http.HandleFunc("/", handler)

	log.Fatalln(http.Serve(listener, nil))
}

