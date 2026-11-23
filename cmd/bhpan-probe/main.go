// bhpan-probe reads credentials from stdin and emits aggregate results only.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/StuHelper/stuhelper-storage-bhpan"
	"github.com/StuHelper/stuhelper-storage-bhpan/internal/probe"
)

func main() {
	err := probe.Run(context.Background(), bhpan.Config{}, os.Stdin, os.Stdout)
	if err != nil {
		if err == probe.ErrInvalidInput {
			fmt.Fprintln(os.Stderr, err.Error())
		}
		os.Exit(1)
	}
}
