package main

import (
  "github.com/Graylog2/go-gelf/gelf"
  "github.com/fsnotify/fsnotify"
  "bytes"
  "time"
  "os"
  "log"
)

// # pos               inode
// # ffffffffffffffff\tffffffffffffffff\n

// account-2152481023-5v8wg_v1_account-38e0b2b97cb2bb1e337a6d3e89075a494a661aa9477a2815ae4d9eda473b0245
// (_kubernetes_pod)_(_kubernetes_namespace)_(_kubernetes_container)_(_docker_container_id)

// stream

// tag: kubernetes.var.log.containers.account-2152481023-5v8wg_v1_account-38e0b2b97cb2bb1e337a6d3e89075a494a661aa9477a2815ae4d9eda473b0245.log

func logContainerMessage(w *gelf.Writer, p []byte, hostname string, metadata map[string]interface{}) (n int, err error) {
  // remove trailing and leading whitespace
  p = bytes.TrimSpace(p)

  // If there are newlines in the message, use the first line
  // for the short message and set the full message to the
  // original input.  If the input has no newlines, stick the
  // whole thing in Short.
  short := p
  full := []byte("")
  if i := bytes.IndexRune(p, '\n'); i > 0 {
    short = p[:i]
    full = p
  }

  m := gelf.Message{
    Version:  "1.1",
    Host:     hostname,
    Short:    string(short),
    Full:     string(full),
    TimeUnix: float64(time.Now().Unix()),
    Level:    6, // info
    Facility: w.Facility,
    Extra: metadata,
  }

  if err = w.WriteMessage(&m); err != nil {
    return 0, err
  }

  return len(p), nil
}

func processFsEvents(watcher *fsnotify.Watcher, writer *gelf.Writer) {
  for {
    select {
      case event := <-watcher.Events:
        if ((event.Op & fsnotify.Write == fsnotify.Write) || (event.Op & fsnotify.Create == fsnotify.Create)) {
            fileName := event.Name
            mmap := make(map[string]interface{})
            logContainerMessage(writer, []byte(fileName), "aa", mmap)
        }
      case err := <-watcher.Errors:
        log.Println("error:", err)
    }
  }
}

func main() {
  finish := make(chan struct{})
  nbGoRoutine := 0
  logDirectory := "/var/log/containers"

  gelfAddr := os.Getenv("GELF_ADDR")
  if gelfAddr == "" {
    log.Fatalf("Missing gelf address.")
  }
  gelfWriter, err := gelf.NewWriter(gelfAddr)

  watcher, err := fsnotify.NewWatcher()
  if err != nil {
    log.Fatal(err)
  }
  defer watcher.Close()

  nbGoRoutine += 1
  go func() {
    processFsEvents(watcher, gelfWriter)
    finish <- struct{}{}
  }()

  err = watcher.Add(logDirectory)
  if err != nil {
    log.Fatal(err)
  }

  for i := 0; i < nbGoRoutine; i++ { // Wait for goroutine to finish --'
    <- finish
  }
}

