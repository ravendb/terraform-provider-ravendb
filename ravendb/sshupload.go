package ravendb

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
	"path"
	"path/filepath"
)

func (sc *ServerConfig) UploadLicense(c *ssh.Client) error {

	session, err := c.NewSession()
	if err != nil {
		fmt.Printf("Cannot create SSH session to %v\n", c)
		fmt.Println(err)
		os.Exit(2)
	}

	defer c.Conn.Close()

	etargetFile := path.Join("/home/targetDir/")
	//go func() {
	w, err := session.StdinPipe()
	if err != nil {
		panic(err)
	}
	defer w.Close()

	src, err := os.Open("README.md")
	panicOnError("os.Open", err)
	defer src.Close()

	srcStat, err := os.Stat("README.md")
	if err != nil {
		panic(err)
	}

	targetFile := filepath.Base(etargetFile)
	_, err = fmt.Fprintln(w, "C0644", srcStat.Size(), targetFile)
	panicOnError("C0644", err)

	if srcStat.Size() > 0 {
		n, err := io.Copy(w, src)
		panicOnError("Copy", err)
		fmt.Println(n)

		_, err = fmt.Fprint(w, "\x00")
		panicOnError("\x00", err)

	} else {
		_, err = fmt.Fprint(w, "\x00")
		panicOnError("\x00", err)

	}

	fmt.Println("start upload")
	err = session.Run(fmt.Sprintf("scp -tr %s", etargetFile))
	panicOnError("Run scp", err)
	session.Close()

	return nil
}

func panicOnError(msg string, err error) {
	if err != nil {
		panic(fmt.Errorf("%s: %v", msg, err))
	}
}
