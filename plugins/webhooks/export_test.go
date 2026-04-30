package webhooks

import (
	"time"

	"github.com/yackey-labs/yauth-go/domain"
)

// NewDeliveryJobForTest constructs a deliveryJob from raw fields. It
// exists so external test packages can drive the dispatcher directly
// without spinning up the full event-handler pipeline.
func NewDeliveryJobForTest(webhook domain.Webhook, eventType string, data map[string]any) *deliveryJob {
	return &deliveryJob{
		webhook:   webhook,
		eventType: eventType,
		payload: payloadEnvelope{
			Event:     eventType,
			Timestamp: time.Now().UTC(),
			Data:      data,
		},
	}
}
