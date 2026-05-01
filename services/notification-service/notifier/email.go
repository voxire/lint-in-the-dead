package notifier

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"

	"github.com/voxire/lint-in-the-dead/pkg/models"
)

type Email struct {
	host string
	port string
	user string
	pass string
	from string
}

func NewEmail(host, port, user, pass, from string) *Email {
	return &Email{host: host, port: port, user: user, pass: pass, from: from}
}

func (e *Email) Enabled() bool { return e.host != "" && e.user != "" }

func (e *Email) Send(_ context.Context, req models.NotificationRequest, to []string) error {
	if !e.Enabled() || len(to) == 0 {
		return nil
	}

	result := req.Result
	subject := fmt.Sprintf("[lint-in-the-dead] %s/%s — analysis %s (score %.0f)",
		result.RepoOwner, result.RepoName,
		statusLabel(result.Summary.Passed),
		result.Summary.Score,
	)

	body := fmt.Sprintf(
		"Repository: %s/%s\nCommit: %s\nScore: %.0f/100\n\nFindings:\n"+
			"  Critical: %d\n  High: %d\n  Medium: %d\n  Low: %d\n  Total: %d\n\n"+
			"Duration: %dms\n",
		result.RepoOwner, result.RepoName,
		result.CommitSHA,
		result.Summary.Score,
		result.Summary.BySeverity["critical"],
		result.Summary.BySeverity["high"],
		result.Summary.BySeverity["medium"],
		result.Summary.BySeverity["low"],
		result.Summary.TotalFindings,
		result.DurationMS,
	)

	msg := "From: " + e.from + "\r\n" +
		"To: " + strings.Join(to, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		body

	addr := net.JoinHostPort(e.host, e.port)
	auth := smtp.PlainAuth("", e.user, e.pass, e.host)

	// Try STARTTLS first; fall back to plain TLS on 465.
	if e.port == "465" {
		return e.sendTLS(addr, auth, to, []byte(msg))
	}
	return smtp.SendMail(addr, auth, e.from, to, []byte(msg))
}

func (e *Email) sendTLS(addr string, auth smtp.Auth, to []string, msg []byte) error {
	tlsCfg := &tls.Config{ServerName: e.host}
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	client, err := smtp.NewClient(conn, e.host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Quit()
	if err := client.Auth(auth); err != nil {
		return err
	}
	if err := client.Mail(e.from); err != nil {
		return err
	}
	for _, t := range to {
		if err := client.Rcpt(t); err != nil {
			return err
		}
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}
	defer wc.Close()
	_, err = wc.Write(msg)
	return err
}
