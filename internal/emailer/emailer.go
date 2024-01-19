package emailer

import (
	"crypto/tls"

	"github.com/M0hammedImran/go-server-template/internal/core/config"
	"github.com/M0hammedImran/go-server-template/internal/core/logging"
	"gopkg.in/mail.v2"
)

const (
	MESSAGE_FORMAT = "From: %s\r\nTo: %s\r\nSubject: %s\r\n%s"
)

type Emailer interface {
	SendEmail(email Email) error
}

type emailer struct {
	host     string
	port     int
	email    string
	password string
}

type Email struct {
	To      []string
	Subject string
	Body    string
}

func NewHandler(config *config.Config) Emailer {
	email := config.SMTPConfig.Username
	password := config.SMTPConfig.Password
	host := config.SMTPConfig.Host
	port := config.SMTPConfig.Port

	return &emailer{
		host:     host,
		port:     port,
		email:    email,
		password: password,
	}
}

func (sc emailer) SendEmail(email Email) error {

	d := mail.NewDialer(sc.host, sc.port, sc.email, sc.password)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	m := mail.NewMessage()
	m.SetHeader("From", sc.email)
	m.SetHeader("To", email.To...)
	m.SetHeader("Subject", email.Subject)
	m.SetBody("text/plain", email.Body)

	if err := d.DialAndSend(m); err != nil {
		logging.DefaultLogger().Errorw("Error sending email", "err", err)
		return (err)
	}

	return nil
}
