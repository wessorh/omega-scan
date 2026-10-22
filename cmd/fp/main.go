// fp — print the omega-scan holloman3 fingerprint for each file argument.
// Output: "<order_char><32 hex>" (33 chars), one per line.

package main

import (
	"fmt"
	"os"

	"github.com/support-intelligence/omega-scan/fingerprint"
)

func main() {
	if err := fingerprint.Init(13); err != nil {
		fmt.Fprintf(os.Stderr, "Init: %v\n", err)
		os.Exit(1)
	}
	defer fingerprint.Cleanup()

	for _, path := range os.Args[1:] {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Println("READERR")
			continue
		}
		fp, err := fingerprint.FingerprintBuffer(data)
		if err != nil {
			fmt.Println("REJECT")
			continue
		}
		order, _ := fingerprint.CalculateOrder(int64(len(data)))
		var c byte
		if int(order) < len(fingerprint.OrderAlphabet) {
			c = fingerprint.OrderAlphabet[order]
		} else {
			c = '?'
		}
		fmt.Printf("%c%032x\n", c, fp)
	}
}
