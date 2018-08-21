package providers

import (
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"github.com/buzzfeed/sso/internal/auth/circuit"
	log "github.com/buzzfeed/sso/internal/pkg/logging"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"

	"github.com/datadog/datadog-go/statsd"
)

// AdminService wraps calls to provider admin APIs
type AdminService interface {
	GetMembers(string) ([]string, error)
	GetGroups(string) ([]string, error)
}

// GoogleAdminService is an AdminService for the google provider
type GoogleAdminService struct {
	adminService *admin.Service
	StatsdClient *statsd.Client
	cb           *circuit.Breaker
}

func getAdminService(adminEmail string, credentialsReader io.Reader) *admin.Service {
	logger := log.NewLogEntry()

	data, err := ioutil.ReadAll(credentialsReader)
	if err != nil {
		logger.WithError(err).Fatal("can't read Google credentials file")
	}
	conf, err := google.JWTConfigFromJSON(data, admin.AdminDirectoryUserReadonlyScope, admin.AdminDirectoryGroupReadonlyScope)
	if err != nil {
		logger.WithError(err).Fatal("can't load Google credentials file")
	}
	conf.Subject = adminEmail

	client := conf.Client(oauth2.NoContext)
	adminService, err := admin.New(client)
	if err != nil {
		logger.WithError(err).Fatal()
	}
	return adminService
}

// GetMembers returns the members of a google group
func (gs *GoogleAdminService) GetMembers(groupName string) ([]string, error) {
	var members []string
	tags := []string{
		"provider:google",
		"action:members_resource",
		fmt.Sprintf("group:%s", groupName),
	}

	pageToken := ""
	for {
		startTS := time.Now()

		// get pages of 200 members in a group
		req := gs.adminService.Members.List(groupName).MaxResults(200)
		if pageToken != "" {
			req.PageToken(pageToken)
		}
		gs.StatsdClient.Incr("provider.request", tags, 1.0)

		resp, err := gs.cb.Call(func() (interface{}, error) {
			return req.Do()
		})
		if err != nil {
			switch e := err.(type) {
			case *googleapi.Error:
				tags = append(tags, fmt.Sprintf("status_code:%d", e.Code))
				gs.StatsdClient.Incr("provider.response", tags, 1.0)
				gs.StatsdClient.Incr("provider.error", tags, 1.0)
				switch e.Code {
				case 400:
					if e.Error() == "Token expired or revoked" {
						err = ErrTokenRevoked
					}
					err = ErrBadRequest
				case 429:
					err = ErrRateLimitExceeded
				case 503:
					err = ErrServiceUnavailable
				}
			case *circuit.ErrOpenState:
				tags = append(tags, "circuit:open")
				gs.StatsdClient.Incr("provider.error", tags, 1.0)
			default:
				tags = append(tags, "error:invalid_response")
				gs.StatsdClient.Incr("provider.internal_error", tags, 1.0)
			}
			return nil, err
		}

		r := resp.(*admin.Members)

		tags = append(tags, fmt.Sprintf("status_code:%d", r.HTTPStatusCode))
		gs.StatsdClient.Timing("provider.latency", time.Now().Sub(startTS), tags, 1.0)
		gs.StatsdClient.Incr("provider.response", tags, 1.0)

		for _, member := range r.Members {
			members = append(members, member.Email)
		}
		if r.NextPageToken == "" {
			break
		}
		pageToken = r.NextPageToken
	}
	return members, nil
}

// GetGroups gets the groups that a user with a given email address belongs to.
func (gs *GoogleAdminService) GetGroups(email string) ([]string, error) {
	var groups []string
	tags := []string{
		"provider:google",
		"action:groups_resource",
	}
	pageToken := ""
	for {
		startTS := time.Now()

		// get pages of 200 groups for an email
		req := gs.adminService.Groups.List().MaxResults(200).UserKey(email)
		if pageToken != "" {
			req.PageToken(pageToken)
		}
		gs.StatsdClient.Incr("provider.request", tags, 1.0)

		resp, err := gs.cb.Call(func() (interface{}, error) {
			return req.Do()
		})
		if err != nil {
			switch e := err.(type) {
			case *googleapi.Error:
				tags = append(tags, fmt.Sprintf("status_code:%d", e.Code))
				gs.StatsdClient.Incr("provider.response", tags, 1.0)
				gs.StatsdClient.Incr("provider.error", tags, 1.0)
				switch e.Code {
				case 400:
					if e.Error() == "Token expired or revoked" {
						err = ErrTokenRevoked
					}
					err = ErrBadRequest
				case 429:
					err = ErrRateLimitExceeded
				case 503:
					err = ErrServiceUnavailable
				}
			case *circuit.ErrOpenState:
				tags = append(tags, "circuit:open")
				gs.StatsdClient.Incr("provider.error", tags, 1.0)
			default:
				tags = append(tags, "error:invalid_response")
				gs.StatsdClient.Incr("provider.internal_error", tags, 1.0)
			}
			return nil, err
		}

		r := resp.(*admin.Groups)

		tags = append(tags, fmt.Sprintf("status_code:%d", r.HTTPStatusCode))
		gs.StatsdClient.Timing("provider.latency", time.Now().Sub(startTS), tags, 1.0)
		gs.StatsdClient.Incr("provider.response", tags, 1.0)

		for _, group := range r.Groups {
			groups = append(groups, group.Email)
		}
		if r.NextPageToken == "" {
			break
		}
		pageToken = r.NextPageToken
	}
	return groups, nil
}
