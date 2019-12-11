package managers

import (
	"context"
	"strings"

	"code.cloudfoundry.org/lager"
	"github.com/go-pg/pg/v9"
)

// todo (mxplusb): figure out a common request and response object that can be inherited.

type Response struct {
	InstanceId string
	Error      error
	Ok         bool
	NotFound   bool
}

type dbTestlogger struct {
	logger lager.Logger
}

func (d dbTestlogger) BeforeQuery(c context.Context, q *pg.QueryEvent) (context.Context, error) {
	return c, nil
}

func (d dbTestlogger) AfterQuery(c context.Context, q *pg.QueryEvent) error {
	f, err := q.FormattedQuery()
	d.logger.Info("query", lager.Data{
		"statement":    f,
		"format-error": err,
	})
	return nil
}

func notFound(err error) bool {
	if strings.Contains(err.Error(), errNotFound) {
		return true
	}
	return false
}
