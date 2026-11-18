package backup

import (
	"fmt"
	"strconv"
	"strings"
)

var dowNames = []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}

// Describe renders a short English description of common cron shapes for
// the schedule preview; anything unusual falls back to the expression.
func Describe(expr, tz string) string {
	if tz == "" {
		tz = "UTC"
	}
	switch expr {
	case "@hourly":
		return "Every hour (" + tz + ")"
	case "@daily", "@midnight":
		return "At 00:00 every day (" + tz + ")"
	case "@weekly":
		return "At 00:00 every Sunday (" + tz + ")"
	case "@monthly":
		return "At 00:00 on day 1 of every month (" + tz + ")"
	}
	f := strings.Fields(expr)
	if len(f) != 5 {
		return fmt.Sprintf("Cron %q (%s)", expr, tz)
	}
	min, errM := strconv.Atoi(f[0])
	hour, errH := strconv.Atoi(f[1])
	dom, mon, dow := f[2], f[3], f[4]
	if errM == nil && f[1] == "*" && dom == "*" && mon == "*" && dow == "*" {
		return fmt.Sprintf("Every hour at minute %d (%s)", min, tz)
	}
	if errM != nil || errH != nil || mon != "*" {
		return fmt.Sprintf("Cron %q (%s)", expr, tz)
	}
	at := fmt.Sprintf("At %02d:%02d", hour, min)
	switch {
	case dom == "*" && dow == "*":
		return at + " every day (" + tz + ")"
	case dom == "*":
		if d, err := strconv.Atoi(dow); err == nil && d >= 0 && d <= 7 {
			return at + " every " + dowNames[d] + " (" + tz + ")"
		}
		if dow == "1-5" || strings.EqualFold(dow, "MON-FRI") {
			return at + " on weekdays (" + tz + ")"
		}
	case dow == "*":
		if d, err := strconv.Atoi(dom); err == nil {
			return fmt.Sprintf("%s on day %d of every month (%s)", at, d, tz)
		}
	}
	return fmt.Sprintf("Cron %q (%s)", expr, tz)
}
