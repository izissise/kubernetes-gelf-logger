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

type fileInfos struct {
  seek uint64
  inode uint64
  filename string
  file *os.File
  metadata map[string]interface{}
}

type loggerData struct {
  files map[string]*fileInfos
  hostname string
  writer *gelf.Writer
  watcher *fsnotify.Watcher
}

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
  log.Printf("%s", m.Short) // Remove this

  return len(p), nil
}

func writeFileInfos(files map[string]*fileInfos) {

}

func fileUpdate(kgl *loggerData, filename string) {
  fi := kgl.files[filename]
  buff := make([]byte, 4096)
  size, err := fi.file.Read(buff)
  if (err == nil) {
    logContainerMessage(kgl.writer, buff[:size], kgl.hostname, fi.metadata)
    // Update seek value
    writeFileInfos(kgl.files)
  }
}

func newFile(kgl *loggerData, filename string) {
  f, err := os.Open(filename)
  if (err != nil) {
    panic(err)
  }
  fi := new(fileInfos);
  fi.file = f
  fi.seek = 0 // retrieve seek position
//   f.Seek(6, 0)
  fi.inode = 0 // Inode
  fi.filename = filename
  fi.metadata = make(map[string]interface{}) // Parse filename infos
  kgl.files[filename] = fi
}

func unfollowFile(kgl *loggerData, filename string) {
  fi := kgl.files[filename]
  if (fi != nil) {
    fi.file.Close()
    writeFileInfos(kgl.files)
    delete(kgl.files, filename)
  }
}

func processFsEvents(kgl *loggerData) {
  for {
    select {
      case event := <-kgl.watcher.Events:
        fileName := event.Name
        if (event.Op & fsnotify.Create == fsnotify.Create) {
          newFile(kgl, fileName)
        }
        if ((event.Op & fsnotify.Create == fsnotify.Create) || (event.Op & fsnotify.Write == fsnotify.Write)) {
          fileUpdate(kgl, fileName)
        } else {
          unfollowFile(kgl, fileName) // Probably a log rotate
        }
      case err := <-kgl.watcher.Errors:
        log.Println("error:", err)
    }
  }
}

func main() {
  finish := make(chan struct{})
  nbGoRoutine := 0

  logDirectory := "/var/log/containers"
  kgl := new(loggerData)
  kgl.files = make(map[string]*fileInfos)

  gelfAddr := os.Getenv("GELF_ADDR")
  if gelfAddr == "" {
    log.Fatalf("Missing gelf address.")
  }
  gelfWriter, err := gelf.NewWriter(gelfAddr)
  kgl.writer = gelfWriter

  watcher, err := fsnotify.NewWatcher()
  if err != nil {
    log.Fatal(err)
  }
  defer watcher.Close()
  kgl.watcher = watcher

  nbGoRoutine += 1
  go func() {
    processFsEvents(kgl)
    finish <- struct{}{}
  }()

  err = kgl.watcher.Add(logDirectory)
  if err != nil {
    log.Fatal(err)
  }

  for i := 0; i < nbGoRoutine; i++ { // Wait for goroutine to finish --'
    <- finish
  }
}

