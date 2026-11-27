package controller

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/ybkuroki/go-webapp-sample/container"
	"github.com/ybkuroki/go-webapp-sample/model"
)

// SearchBooksByAuthor returns the books whose author matches the name query parameter.
func SearchBooksByAuthor(container container.Container) echo.HandlerFunc {
	return func(c echo.Context) error {
		var books []model.Book
		query := fmt.Sprintf("SELECT * FROM book WHERE author = '%s'", c.QueryParam("name"))
		if err := container.GetRepository().Raw(query).Scan(&books).Error; err != nil {
			return c.JSON(http.StatusBadRequest, err.Error())
		}
		return c.JSON(http.StatusOK, books)
	}
}
