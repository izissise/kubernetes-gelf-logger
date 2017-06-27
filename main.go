package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"github.com/Graylog2/go-gelf/gelf"
	"github.com/fsnotify/fsnotify"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type fileInfos struct {
	seek     int64
	inode    uint64
	filename string
	file     *os.File
	reader   *bufio.Reader
	metadata map[string]interface{}
}

type Logger struct {
	files        map[string]*fileInfos
	posFile      *os.File
	hostname     string
	writer       *gelf.Writer
	dirWatcher   *fsnotify.Watcher
	filesWatcher *fsnotify.Watcher
	realFilesMap map[string]string
}

type DockerLog struct {
	Log    string    `json:"log"`
	Stream string    `json:"stream"`
	Time   time.Time `json:"time"`
}

func inverseMap(m map[string]string, value string) string {
	for k, v := range m {
		if v == value {
			return k
		}
	}
	return ""
}

func isLogFile(filename string) bool {
	matched, _ := regexp.MatchString(".+log$", filename)
	return matched
}

func readSymlink(path string) string {
	link, err := os.Readlink(path)
	if err != nil {
		return path
	}
	return link
}

func getInode(filename string) uint64 {
	var stat syscall.Stat_t
	if err := syscall.Stat(filename, &stat); err != nil {
		panic(err)
	}
	inode := stat.Ino
	return inode
}

func gelfMessageFromDockerJsonLog(w *gelf.Writer, p []byte, facility string, hostname string, metadata map[string]interface{}) (n int, err error) {
	var dockLog DockerLog
	err = json.Unmarshal(p, &dockLog)
	if err != nil {
		log.Printf("%s %s\n", err, p)
		return
	}

	// If there are newlines in the message, use the first line
	// for the short message and set the full message to the
	// original input.  If the input has no newlines, stick the
	// whole thing in Short.
	strings.TrimRight(dockLog.Log, "\n")
	mess := []byte(dockLog.Log)
	short := mess
	full := []byte("")
	if i := bytes.IndexRune(short, '\n'); i > 0 {
		short = mess[:i]
		full = mess
	}

	meta := make(map[string]interface{})
	meta["stream"] = dockLog.Stream
	for k, v := range metadata {
		meta[k] = v
	}
	m := gelf.Message{
		Version:  "1.1",
		Host:     hostname,
		Short:    string(short),
		Full:     string(full),
		TimeUnix: float64(dockLog.Time.Unix()),
		Level:    6, // info
		Facility: facility,
		Extra:    metadata,
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
		if len(line) > 0 {
			gelfMessageFromDockerJsonLog(kgl.writer, []byte(line), "KGL", kgl.hostname, fi.metadata)
		}
		fi.seek = fi.seek + int64(size)
	}
	kgl.writeFileInfos()
}

func (kgl *Logger) newFile(filename string) *fileInfos {
	realFile := readSymlink(filename)
	f, err := os.OpenFile(realFile, os.O_RDONLY, 0000)
	if err != nil {
		panic(err)
	}
	log.Printf("New file %s\n", filename)
	fi := kgl.files[filename]
	inode := getInode(realFile)
	if fi == nil {
		fi = new(fileInfos)
		fi.seek = 0
		fi.inode = inode // Set Inode
	}
	fi.file = f
	if fi.inode != inode {
		fi.inode = inode // Update inode
	} else {
		_, err = fi.file.Seek(fi.seek, 0) // Seek to position
		if err != nil {
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

	kgl.filesWatcher.Add(realFile)        // Add watcher
	kgl.realFilesMap[realFile] = filename // Add in map
	return fi
}

func (kgl *Logger) unfollowFile(filename string) {
	fi := kgl.files[filename]
	if fi != nil {
		fi.file.Close()
		kgl.writeFileInfos()
		delete(kgl.files, filename)
		log.Printf("Unfollow %s\n", filename)
	}
}

func (kgl *Logger) processFsEvents() {
	for {
		select {
		// Symlink dir events
		case event := <-kgl.dirWatcher.Events:
			filename := event.Name
			if isLogFile(filename) {
				if event.Op&fsnotify.Create == fsnotify.Create || (event.Op&fsnotify.Write == fsnotify.Write) {
					kgl.newFile(filename)
				} else {
					realFile := inverseMap(kgl.realFilesMap, filename)
					kgl.filesWatcher.Remove(realFile)  // Remove watch
					delete(kgl.realFilesMap, realFile) // Remove from map
				}
			}
		case err := <-kgl.dirWatcher.Errors:
			log.Println("error:", err)

		// Files events
		case event := <-kgl.filesWatcher.Events:
			filename := event.Name
			if (event.Op&fsnotify.Create == fsnotify.Create) || (event.Op&fsnotify.Write == fsnotify.Write) {
				kgl.fileUpdate(kgl.realFilesMap[filename])
			} else {
				kgl.unfollowFile(kgl.realFilesMap[filename]) // Probably a log rotate
			}
		case err := <-kgl.filesWatcher.Errors:
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
		fi := new(fileInfos)
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
	host, _ := os.Hostname()
	kgl.hostname = host
	kgl.realFilesMap = make(map[string]string)
	kgl.files = make(map[string]*fileInfos)
	f, err := os.OpenFile(posFile, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
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

	filesWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer filesWatcher.Close()
	kgl.filesWatcher = filesWatcher

	files, _ := ioutil.ReadDir(logDirectory)
	for _, f := range files {
		if isLogFile(f.Name()) && !f.IsDir() {
			kgl.newFile(logDirectory + "/" + f.Name())
		}
	}

	dirWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer dirWatcher.Close()
	kgl.dirWatcher = dirWatcher

	nbGoRoutine += 1
	go func() {
		kgl.processFsEvents()
		finish <- struct{}{}
	}()

	err = kgl.dirWatcher.Add(logDirectory)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < nbGoRoutine; i++ { // Wait for goroutine to finish --'
		<-finish
	}
}
