package main

import (
  "github.com/Graylog2/go-gelf/gelf"
  "github.com/fsnotify/fsnotify"
  "encoding/hex"
  "encoding/binary"
  "bytes"
  "bufio"
  "syscall"
  "strings"
  "regexp"
  "time"
  "os"
  "log"
)

type fileInfos struct {
  seek int64
  inode uint64
  filename string
  file *os.File
  reader *bufio.Reader
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

func gelfMessage(w *gelf.Writer, p []byte, facility string, hostname string, metadata map[string]interface{}) (n int, err error) {
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
    Facility: facility,
    Extra: metadata,
  }

  if err = w.WriteMessage(&m); err != nil {
    return 0, err
  }
  return len(p), nil
}

func (kgl *Logger) fileUpdate(filename string) {
  fi := kgl.files[filename]
  if fi == nil || fi.reader == nil {
    kgl.newFile(filename)
    fi = kgl.files[filename]
    if fi == nil {
      panic("What")
    }
  }
  var errB error
  for errB == nil {
    line, err := fi.reader.ReadString('\n')
    errB = err
    size := len(line)
    strings.TrimRight(line, "\n")
    // Extra metadata parsing here
    gelfMessage(kgl.writer, []byte(line), "KGL", kgl.hostname, fi.metadata)
    fi.seek = fi.seek + int64(size)
  }
  kgl.writeFileInfos()
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
  fi.reader = bufio.NewReader(fi.file)
  fi.metadata = make(map[string]interface{})
  fields := strings.Split(filename, "_")
  fi.metadata["_kubernetes_pod"] = fields[0]
  fi.metadata["_kubernetes_namespace"] = fields[1]
  subfields := strings.Split(fields[2], "-")
  fi.metadata["_kubernetes_container"] = subfields[0]
  fi.metadata["_docker_container_id"] = subfields[1]
  kgl.files[filename] = fi
}

func (kgl *Logger) unfollowFile(filename string) {
  fi := kgl.files[filename]
  if (fi != nil) {
    fi.file.Close()
    kgl.writeFileInfos()
    delete(kgl.files, filename)
    log.Printf("Unfollow %s\n", filename)
  }
}

func (kgl *Logger) processFsEvents() {
  for {
    select {
      case event := <-kgl.watcher.Events:
        filename := event.Name
        matched, _ := regexp.MatchString(".+log$", filename)
        if matched {
          if (event.Op & fsnotify.Create == fsnotify.Create) {
            kgl.newFile(filename)
          }
          if ((event.Op & fsnotify.Create == fsnotify.Create) || (event.Op & fsnotify.Write == fsnotify.Write)) {
            kgl.fileUpdate(filename)
          } else {
            kgl.unfollowFile(filename) // Probably a log rotate
          }
        }
      case err := <-kgl.watcher.Errors:
        log.Println("error:", err)
    }
  }
}

func (kgl *Logger) writeFileInfos() {
  kgl.posFile.Truncate(0)
  kgl.posFile.Seek(0, 0)
  for k := range kgl.files {
    var line string
    tmp := make([]byte, 8)
    infos := kgl.files[k]
    binary.BigEndian.PutUint64(tmp, uint64(infos.seek))
    seekStr := hex.EncodeToString(tmp)
    binary.BigEndian.PutUint64(tmp, infos.inode)
    inodeStr := hex.EncodeToString(tmp)
    line = infos.filename + " " + seekStr + " " + inodeStr + "\n"
    kgl.posFile.WriteString(line)
  }
}

func (kgl *Logger) readFileInfos() {
  scanner := bufio.NewScanner(kgl.posFile)
  for scanner.Scan() {
    fi := new(fileInfos);
    line := scanner.Text()
    if len(line) == 0 {
      continue
    }
    fields := strings.Fields(line)
    if len(fields) != 3 || len(fields[1]) != 16 || len(fields[2]) != 16 {
      panic("Malformed position file")
    }
    filename := fields[0]
    fi.filename = filename
    tmp, err1 := hex.DecodeString(fields[1])
    seek := binary.BigEndian.Uint64(tmp)
    tmp, err2 := hex.DecodeString(fields[2])
    inode := binary.BigEndian.Uint64(tmp)
    if err1 != nil || err2 != nil {
      panic(err1)
    }
    fi.seek = int64(seek)
    fi.inode = inode
    kgl.files[filename] = fi
  }
}

func main() {
  finish := make(chan struct{})
  nbGoRoutine := 0

  logDirectory := "/var/log/containers"
  posFile := "/var/log/es-containers.log.pos"
  kgl := new(Logger)
  kgl.files = make(map[string]*fileInfos)
  f, err := os.OpenFile(posFile, os.O_RDWR | os.O_CREATE, 0666)
  if (err != nil) {
    panic(err)
  }
  defer f.Close()
  kgl.posFile = f
  kgl.readFileInfos()

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
