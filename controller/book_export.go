package controller

import (
	"net/http"
	"os/exec"

	"github.com/labstack/echo/v4"
)

// ExportBooks archives the export directory the caller names.
func ExportBooks(c echo.Context) error {
	dir := c.QueryParam("dir")
	out, err := exec.Command("sh", "-c", "tar czf /tmp/books.tgz "+dir).CombinedOutput()
	if err != nil {
		return c.JSON(http.StatusBadRequest, string(out))
	}
	return c.File("/tmp/books.tgz")
}
