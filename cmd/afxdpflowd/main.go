// afxdpflowd — future AF_XDP flow collector (UMEM + xsk, branch feature/afxdp).
// Does not replace xdpflowd on main until feature-complete.
package main

import (
	"flag"
	"fmt"
	"os"

	"xdpflowd/internal/afxdp"
)

func main() {
	ver := flag.Bool("version", false, "print version and exit")
	iface := flag.String("iface", "", "interface (required when not -version)")
	flag.Parse()
	if *ver {
		fmt.Println("afxdpflowd 0-dev (WIP) —", afxdp.Version)
		return
	}
	if *iface == "" {
		fmt.Fprintln(os.Stderr, "usage: afxdpflowd -iface <dev>  (or -version)")
		fmt.Fprintln(os.Stderr, "See internal/afxdp for layout; binary is a stub on feature/afxdp branch.")
		os.Exit(2)
	}
	_ = *iface
	// TODO: afxdp.Config, UMEM, xsk per queue, flow aggregate, netv9 export
	fmt.Fprintln(os.Stderr, "afxdpflowd: not implemented — built for CI/layout only")
	os.Exit(1)
}
