package main

import (
  "github.com/Graylog2/go-gelf/gelf"
  "github.com/fsnotify/fsnotify"
  "bytes"
  "syscall"
  "strings"
  "time"
  "os"
  "log"
)

// stream

type fileInfos struct {
  seek int64
  inode uint64
  filename string
  file *os.File
  metadata map[string]interface{}
}

type Logger struct {
  files map[string]*fileInfos
  posFile *os.File
  hostname string
  writer *gelf.Writer
  watcher *fsnotify.Watcher
}

func getInode(filename string) uint64 {
  var stat syscall.Stat_t
  if err := syscall.Stat(filename, &stat); err != nil {
    panic(err)
  }
  inode := stat.Ino
  return inode
}

func gelfMessage(w *gelf.Writer, p []byte, hostname string, metadata map[string]interface{}) (n int, err error) {
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

func (kgl *Logger) fileUpdate(filename string) {
  fi := kgl.files[filename]
  if fi == nil {
    return
  }
  buff := make([]byte, 4096)
  size, err := fi.file.Read(buff)
  if (err == nil) {
    gelfMessage(kgl.writer, buff[:size], kgl.hostname, fi.metadata)
//     // Find the current position by getting the
//     // return value from Seek after moving 0 bytes
//     currentPosition, err := fi.file.Seek(0, 1)
//     if (err != nil) {
//       panic(err)
//     }
    currentPosition := fi.seek + int64(size)
    fi.seek = currentPosition;
    kgl.writeFileInfos()
  }
}

func (kgl *Logger) newFile(filename string) {
  f, err := os.OpenFile(filename, os.O_RDONLY, 0000)
  if (err != nil) {
    panic(err)
  }
  log.Printf("New file %s\n", filename)
  fi := kgl.files[filename]
  inode := getInode(filename)
  if fi == nil {
    fi = new(fileInfos);
    fi.seek = 0
    fi.inode = inode // Set Inode
  }
  fi.file = f
  if fi.inode != inode {
    fi.inode = inode // Update inode
  } else {
    _, err = fi.file.Seek(fi.seek, 0) // Seek to position
    if (err != nil) {
      panic(err)
    }
  }
  fi.filename = filename
  fi.metadata = make(map[string]interface{})
  fields := strings.Split(filename, "_")
  fi.metadata["_kubernetes_pod"] = fields[0]
  fi.metadata["_kubernetes_namespace"] = fields[1]
  subfields := strings.Split(fields[2], "-")
  fi.metadata["_kubernetes_container"] = subfields[0]
  fi.metadata["_docker_container_id"] = subfields[1]
//   fi.metadata["stream"] = ??
  kgl.files[filename] = fi
}

func (kgl *Logger) unfollowFile(filename string) {
  fi := kgl.files[filename]
  log.Printf("Unfollow %s\n", filename)
  if (fi != nil) {
    fi.file.Close()
    kgl.writeFileInfos()
    delete(kgl.files, filename)
  }
}

func (kgl *Logger) processFsEvents() {
  for {
    select {
      case event := <-kgl.watcher.Events:
        fileName := event.Name
        if (event.Op & fsnotify.Create == fsnotify.Create) {
          kgl.newFile(fileName)
        }
        if ((event.Op & fsnotify.Create == fsnotify.Create) || (event.Op & fsnotify.Write == fsnotify.Write)) {
          kgl.fileUpdate(fileName)
        } else {
          kgl.unfollowFile(fileName) // Probably a log rotate
        }
      case err := <-kgl.watcher.Errors:
        log.Println("error:", err)
    }
  }
}

func (kgl *Logger) writeFileInfos() {

}

func main() {
  finish := make(chan struct{})
  nbGoRoutine := 0

  logDirectory := "/var/log/containers"
  kgl := new(Logger)
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
    kgl.processFsEvents()
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

