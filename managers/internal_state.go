package managers

import (
	"time"

	"github.com/jinzhu/gorm"
)

// Internal state information about the broker's start and stop times.
type ProcInfo struct {
	gorm.Model
	Start time.Time
	Stop time.Time
}
