package gormrepo

import (
	"context"

	"gorm.io/gorm"
)

// Migrate runs AutoMigrate for all yauth-go MVP tables.
func Migrate(ctx context.Context, db *gorm.DB) error {
	tx := db.WithContext(ctx)
	if tx.Dialector.Name() == "sqlite" {
		if err := tx.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
			return err
		}
	}
	return tx.AutoMigrate(
		&User{},
		&Session{},
		&Password{},
		&PasswordHistory{},
		&EmailVerification{},
		&PasswordReset{},
		&AuditLog{},
		&Challenge{},
		&RateLimit{},
		&Revocation{},
		&OAuthState{},
		&MagicLink{},
		&OAuth2Client{},
		&Webhook{},
		&OIDCNonce{},
		&WebauthnCredential{},
		&TOTPSecret{},
		&BackupCode{},
		&OAuthAccount{},
		&RefreshToken{},
		&APIKey{},
		&AuthorizationCode{},
		&Consent{},
		&DeviceCode{},
		&AccountLock{},
		&UnlockToken{},
		&WebhookDelivery{},
		&WebhookRetry{},
		&Organization{},
		&Membership{},
		&Invitation{},
	)
}
