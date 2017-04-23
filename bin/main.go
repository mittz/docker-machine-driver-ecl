package main

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	"github.com/mittz/docker-machine-driver-ecl"
)

func main() {
	plugin.RegisterDriver(ecl.NewDriver("",""))
}

