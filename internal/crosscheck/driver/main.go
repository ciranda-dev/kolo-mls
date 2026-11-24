// Command driver answers interop client requests for kolo-mls, one JSON
// object per line on standard input and output.
package main

import (
	"fmt"
	"os"

	"github.com/ciranda-dev/kolo-mls/internal/crosscheck"
)

func main() {
	if err := crosscheck.NewClient().Serve(os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
