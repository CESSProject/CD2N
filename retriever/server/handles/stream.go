package handles

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/CESSProject/CD2N/retriever/gateway"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

func ServeStream(c *gin.Context, info gateway.DataInfo) error {
	fpath := info.Path
	if info.DecryptedFilePath != "" {
		fpath = info.DecryptedFilePath
	}

	file, err := os.Open(fpath)
	if err != nil {
		return errors.Wrapf(err, "failed to open stream file at %s", fpath)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return errors.Wrap(err, "failed to stat stream file")
	}

	if stat.IsDir() {
		return errors.New("cannot stream a directory")
	}

	contentType := "application/octet-stream"
	if stat.Size() > 0 {
		sniffRange := int64(512)
		if stat.Size() < sniffRange {
			sniffRange = stat.Size()
		}
		
		buf := make([]byte, sniffRange)
		n, err := io.ReadFull(file, buf)
		if err == nil || err == io.ErrUnexpectedEOF {
			contentType = http.DetectContentType(buf[:n])
		}

		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return errors.Wrap(err, "failed to reset file pointer after sniffing")
		}
	}

	cleanName := filepath.Base(info.Name)
	if cleanName == "." || cleanName == "/" {
		cleanName = "file"
	}

	c.Header("Content-Type", contentType)
	c.Header("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", cleanName))
	c.Header("Accept-Ranges", "bytes")
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	http.ServeContent(
		c.Writer,
		c.Request,
		cleanName,
		stat.ModTime(),
		file,
	)

	return nil
}