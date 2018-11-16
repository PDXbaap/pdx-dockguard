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
	"os"
	"syscall"
	"log"
	"os/exec"
	"strings"
	"time"
	"bufio"
	"net/http"
	"net"
	"bytes"
	"io/ioutil"
)

var lockfile = os.Getenv("PDX_HOME")+"/temp/sandbox.lock"
var datafile = os.Getenv("PDX_HOME")+"/temp/sandbox.data"

var startedContainers  = make(map[string]string)

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
		log.Println("illegitimate http method: ", r.Method)
		http.Error(w, "illegitimate http method: " + r.Method, http.StatusUnauthorized)
		return
	}

	log.Println("received cmd: " + cmd)

	args := strings.Split(cmd," ")

	if !accessControl(args) {
		log.Println("unauthorized priviledged access")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// get name of container to be created

	if args[1] == "run" {

		var name string = ""

		for _, v := range args[2:] {
			if strings.HasPrefix(v, "--name") {
				name = strings.Split(v, "=")[1]
				break
			}
		}

		if name == "" {
			log.Println("missing container name, existing ...")
			http.Error(w, "missing container name", http.StatusBadRequest)
			return
		}

		cleanup()

		startedContainers[name] = name

		saveStarted()

		log.Println("starting container: ", name)

	}

	exe := exec.Command(args[0], args[1:]...)

	var out bytes.Buffer
	exe.Stdout = &out
	exe.Stderr = &out
	err := exe.Run()

	if err != nil {
		log.Println("cmd exec error: ", err.Error(), out.String())
		http.Error(w, out.String(), http.StatusBadRequest)
		return
	}

	fmt.Println(w, out.String())

	return
}


func main() {

	var lockF *os.File
	var err error
	for {
		lockF, err = os.OpenFile(lockfile, os.O_CREATE, os.ModePerm)

		err = syscall.Flock(int(lockF.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)

		if err == syscall.EWOULDBLOCK {
			log.Println("another instance running, waiting")
			time.Sleep(100 * time.Millisecond)
			continue
		}

		break
	}

	defer func() {
		syscall.Flock(int(lockF.Fd()), syscall.LOCK_UN)
		lockF.Close()
	}()

	log.Println("now only myself is running")

	loadStarted()


	listener, err := net.Listen("tcp", "127.0.0.1:0")

	if err != nil {
		panic(err)
	}

	log.Printf("listening on: %s", listener.Addr().String())

	http.HandleFunc("/", handler)

	log.Fatal(http.Serve(listener, nil))
}


func accessControl(args []string) bool {

	////////////////////////////////////////////////////////
	//
	// IMPORTANT: sandbox whitelist rules
	//
	// 1) Only allow docker run/stop/stats
	//
	// 2) docker run [OPTIONS] IMAGE [COMMAND] [ARG...]
	//
	//		unprivileged no-harm options only
	//
	// 3) docker stop [OPTIONS] CONTAINER [CONTAINER...]
	//
	// 		only containers started by sandbox
	//
	// 4) docker stats [OPTIONS] [CONTAINER...]
	//
	//		only containers started by sandbox
	//
	//
	// A docker option-with-arg must be in --key=val or -k=val format
	//
    //////////////////////////////////////////////////////

	// only do docker, nothing else

	if args[0] != "docker" {
		log.Println("not a docker binary")
		return false
	}

	// only stats what we have started

	if args[1] == "stats" {

		for _, v := range args[2:] {

			if strings.HasPrefix(v, "-") {
				continue
			}

			if _, ok := startedContainers[v]; !ok {
				log.Println("not a sandboxed container: " + v)
				return false
			}
		}

		return true
	}

	// only stop what we have started

	if args[1] == "stop" {

		for _, v := range args[2:] {

			if strings.HasPrefix(v, "-") {
				continue
			}

			if _, ok := startedContainers[v]; !ok {
				log.Println("not a sandboxed container: " + v)
				return false
			}
		}

		return true
	}

	if args[1] != "run" {
		log.Println("not docker run/stop/stats")
		return false
	}

	// Check docker run [OPTIONS] IMAGE [COMMAND] [ARG...]

	for _,v := range args[2:] {

		if strings.HasPrefix(v,"--privileged") {
			if !strings.Contains(v,"=false") {
				log.Println("unauthorized option: " + v)
				return false
			}
		}

		if strings.HasPrefix(v, "--cap-add") {
			log.Println("unauthorized option: " + v)
			return false
		}

		if strings.HasPrefix(v,"--device") {
			log.Println("unauthorized option: " + v)
			return false
		}

		if strings.HasPrefix(v, "--group-add") {
			log.Println("unauthorized option: " + v)
			return false
		}

		if strings.HasPrefix(v,"--ipc") {
			if strings.Contains(v, "host") || strings.Contains(v, "shareable") ||
				strings.Contains(v, "container:") {
				log.Println("unauthorized ipc mechanism: " + v)
				return false
			}
		}

		if strings.HasPrefix(v, "--security-opt")  {
			if !strings.Contains(v, "no-new-privileges") {
				log.Println("unauthorized security option: " + v)
				return false
			}
		}

		if strings.HasPrefix(v, "-v") || strings.HasPrefix(v, "--volume") {
			if !strings.Contains(v,"ro") {
				log.Println("volume must be read-only: " + v)
				return false;
			}
		}

		if !strings.HasPrefix(v, "-") { //docker image now

			if strings.HasPrefix(v, "pdxbaap/pdx-sandbox") || strings.HasPrefix(v, "pdx-sandbox") ||
				strings.HasPrefix(v, "pdxbaap/pdx-chainstack") || strings.HasPrefix(v, "pdx-chainstack") ||
				strings.HasPrefix(v, "pdxbaap/pdx-blockchain") || strings.HasPrefix(v, "pdx-blockchain") {
				return true
			} else {
				log.Println("malformed option or unauthorized image: " + v)
				return false
			}
		}
	}

	return false
}

func cleanup() {

	// remove dead container ids off the record

	for _, v := range startedContainers {

		//docker inspect -f '{{.State.Running}}' v

		out, err := exec.Command("docker", "-f", "{{.State.Running}}", v).CombinedOutput()

		if err != nil {
			delete(startedContainers, v)
			log.Println("inspect error:", err)
			log.Println("cleanup dead container: ", v)
			continue
		}

		if string(out) != "true" {
			delete(startedContainers, v)
			log.Println("cleanup dead container: ", v)
		}
	}

	log.Println("cleanup done ")
}

func loadStarted() {

	file, err := os.OpenFile(datafile, os.O_RDONLY, os.ModePerm)
	if err != nil {
		log.Println("cannot read data file: ", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		text := scanner.Text()
		log.Println("found started container: " + text)
		startedContainers[text] = text
	}

	if err := scanner.Err(); err != nil {
		log.Println(err)
	}
}

func saveStarted() {

	os.Remove(datafile)

	file, err := os.Create(datafile)
	if err != nil {
		log.Println("cannot write data file: ", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for _, v := range startedContainers {
		log.Println("save started container:" + v)
		fmt.Fprintln(writer, v)
	}

	writer.Flush()
}
