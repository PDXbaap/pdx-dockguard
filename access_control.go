package main

import (
	"strings"
	"log"
)

func accessControl(args []string) (ok bool, reason string, name string) {

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
		return false, "cmd is not docker", ""
	}

	// only stats what we have started

	if args[1] == "stats" {

		for _, v := range args[2:] {

			if strings.HasPrefix(v, "-") {
				continue
			}

			if _, ok := startedContainers[v]; !ok {
				log.Println("not a sandboxed container: " + v)
				return false, "not a sandboxed container", ""
			}
		}

		return true, "", ""
	}

	// only stop what we have started

	if args[1] == "stop" {

		for _, v := range args[2:] {

			if strings.HasPrefix(v, "-") {
				continue
			}

			if _, ok := startedContainers[v]; !ok {
				log.Println("not a sandboxed container: " + v)
				return false, "not a sandboxed container", ""
			}
		}

		return true, "", ""
	}

	if args[1] != "run" {
		log.Println("not docker run/stop/stats")
		return false, "unauthorized docker cmd", ""
	}

	// Check docker run [OPTIONS] IMAGE [COMMAND] [ARG...]

	for _,v := range args[2:] {

		if strings.HasPrefix(v, "--name") {
			name = strings.Split(v, "=")[1]
			continue
		}

		if strings.HasPrefix(v,"--privileged") {
			if !strings.Contains(v,"=false") {
				log.Println("unauthorized option: " + v)
				return false, "unauthorized option: " + v, ""
			}
		}

		if strings.HasPrefix(v, "--cap-add") {
			log.Println("unauthorized option: " + v)
			return false, "unauthorized option: " + v, ""
		}

		if strings.HasPrefix(v,"--device") {
			log.Println("unauthorized option: " + v)
			return false, "unauthorized option: " + v, ""
		}

		if strings.HasPrefix(v, "--group-add") {
			log.Println("unauthorized option: " + v)
			return false, "unauthorized option: " + v, ""
		}

		if strings.HasPrefix(v,"--ipc") {
			if strings.Contains(v, "host") || strings.Contains(v, "shareable") ||
				strings.Contains(v, "container:") {
				log.Println("unauthorized ipc mechanism: " + v)
				return false, "unauthorized option: " + v, ""
			}
		}

		if strings.HasPrefix(v, "--security-opt")  {
			if !strings.Contains(v, "no-new-privileges") {
				log.Println("unauthorized security option: " + v)
				return false, "unauthorized option: " + v, ""
			}
		}

		if strings.HasPrefix(v, "-v") || strings.HasPrefix(v, "--volume") {
			if !strings.Contains(v,"ro") {
				log.Println("volume must be read-only: " + v)
				return false, "unauthorized option: " + v, ""
			}
		}

		if !strings.HasPrefix(v, "-") { //docker image now

			if strings.HasPrefix(v, "pdxbaap/pdx-sandbox") || strings.HasPrefix(v, "pdx-sandbox") ||
				strings.HasPrefix(v, "pdxbaap/pdx-chainstack") || strings.HasPrefix(v, "pdx-chainstack") ||
				strings.HasPrefix(v, "pdxbaap/pdx-blockchain") || strings.HasPrefix(v, "pdx-blockchain") {
				return true, "", name
			} else {
				log.Println("malformed option or unauthorized image: " + v)
				return false, "unauthorized option: " + v, ""
			}
		}
	}

	return false, "", ""
}

