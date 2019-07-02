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
//
// This interface allows the service to be more readily mocked in tests.
type AdminService interface {
	ListMemberships(group string, depth int) (members []string, err error)
	CheckMemberships(groups []string, user string) (inGroups []string, errr error)
}

// GoogleAdminService is an AdminService for the google provider
type GoogleAdminService struct {
	adminService *admin.Service
	StatsdClient *statsd.Client
	cb           *circuit.Breaker
}

func getAdminService(impersonateUser string, credentialsReader io.Reader) *admin.Service {
	logger := log.NewLogEntry()

	data, err := ioutil.ReadAll(credentialsReader)
	if err != nil {
		logger.WithError(err).Fatal("can't read Google credentials file")
	}

	conf, err := google.JWTConfigFromJSON(data, admin.AdminDirectoryUserReadonlyScope, admin.AdminDirectoryGroupReadonlyScope)
	if err != nil {
		logger.WithError(err).Fatal("can't load Google credentials file")
	}

	conf.Subject = impersonateUser
	client := conf.Client(oauth2.NoContext)

	adminService, err := admin.New(client)
	if err != nil {
		logger.WithError(err).Fatal()
	}

	return adminService
}

// ListMemberships returns a slice of the members of a google group
func (gs *GoogleAdminService) ListMemberships(groupName string, maxDepth int) ([]string, error) {
	return gs.listMemberships(groupName, maxDepth, 0)
}

func (gs *GoogleAdminService) listMemberships(groupName string, maxDepth, currentDepth int) ([]string, error) {
	logger := log.NewLogEntry()

	var members []string
	tags := []string{
		"provider:google",
		"action:list_members_resource",
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
				case 404:
					logger.WithUserGroup(groupName).Warn("could not list memberships, user group not found")
					err = ErrGroupNotFound
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
			switch member.Type {
			case "USER":
				members = append(members, member.Email)
			case "GROUP":
				// this is a group, recursively walk down the nested group, up to maxDepth
				if currentDepth >= maxDepth {
					continue
				}
				groupMembers, err := gs.listMemberships(member.Email, maxDepth, currentDepth+1)
				if err != nil {
					return nil, err
				}
				members = append(members, groupMembers...)
			default:
				err := fmt.Errorf("unknown member type %s", member.Type)
				logger.WithError(err).Error("not adding member to group list")
				continue
			}
		}
		if r.NextPageToken == "" {
			break
		}
		pageToken = r.NextPageToken
	}
	return members, nil
}

// CheckMemberships given a list of groups and a user email, returns a string slice of the groups the user is a member of.
// This func leverages the google HasMember endpoint to verify if a user has membership of the given groups.
func (gs *GoogleAdminService) CheckMemberships(groups []string, email string) ([]string, error) {
	logger := log.NewLogEntry()

	tags := []string{
		"provider:google",
		"action:check_memberships_resource",
	}
	inGroups := []string{}

	for _, group := range groups {
		startTS := time.Now()

		// This call includes nested groups so no recursive resolving is required
		req := gs.adminService.Members.HasMember(group, email)
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
				case 404:
					logger.WithUserGroup(group).Warn("could not check memberships, user group not found")
					continue
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

		r := resp.(*admin.MembersHasMember)

		tags = append(tags, fmt.Sprintf("status_code:%d", r.HTTPStatusCode))
		gs.StatsdClient.Timing("provider.latency", time.Now().Sub(startTS), tags, 1.0)
		gs.StatsdClient.Incr("provider.response", tags, 1.0)

		if r.IsMember {
			inGroups = append(inGroups, group)
		}
	}

	return inGroups, nil
}
