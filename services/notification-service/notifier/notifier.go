package notifier

import (
	"context"
	"log"

	"github.com/voxire/lint-in-the-dead/pkg/models"
)

// Dispatcher routes notifications to all configured backends.
type Dispatcher struct {
	slack *Slack
	email *Email
}

func NewDispatcher(slack *Slack, email *Email) *Dispatcher {
	return &Dispatcher{slack: slack, email: email}
}

func (d *Dispatcher) Dispatch(ctx context.Context, req models.NotificationRequest) {
	for _, target := range req.Targets {
		switch target {
		case "slack":
			if err := d.slack.Send(ctx, req); err != nil {
				log.Printf("slack notify: %v", err)
			}
		case "email":
			// Email targets come from req.Meta["email_to"] (comma-separated).
			// For now we log a warning; wiring email recipients requires policy config.
			log.Printf("email notify: no recipients configured for job %s", req.JobID)
		}
	}
}
