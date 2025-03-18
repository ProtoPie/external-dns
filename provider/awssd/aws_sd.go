/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package awssd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	sd "github.com/aws/aws-sdk-go-v2/service/servicediscovery"
	sdtypes "github.com/aws/aws-sdk-go-v2/service/servicediscovery/types"
	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

const (
	sdDefaultRecordTTL = 300

	sdNamespaceTypePublic  = "public"
	sdNamespaceTypePrivate = "private"

	sdInstanceAttrIPV4  = "AWS_INSTANCE_IPV4"
	sdInstanceAttrIPV6  = "AWS_INSTANCE_IPV6"
	sdInstanceAttrCname = "AWS_INSTANCE_CNAME"
	sdInstanceAttrAlias = "AWS_ALIAS_DNS_NAME"
)

var (
	// matches ELB with hostname format load-balancer.us-east-1.elb.amazonaws.com
	sdElbHostnameRegex = regexp.MustCompile(`.+\.[^.]+\.elb\.amazonaws\.com$`)

	// matches NLB with hostname format load-balancer.elb.us-east-1.amazonaws.com
	sdNlbHostnameRegex = regexp.MustCompile(`.+\.elb\.[^.]+\.amazonaws\.com$`)
)

// AWSSDClient is the subset of the AWS Cloud Map API that we actually use. Add methods as required.
// Signatures must match exactly. Taken from https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/servicediscovery
type AWSSDClient interface {
	CreateService(ctx context.Context, params *sd.CreateServiceInput, optFns ...func(*sd.Options)) (*sd.CreateServiceOutput, error)
	DeregisterInstance(ctx context.Context, params *sd.DeregisterInstanceInput, optFns ...func(*sd.Options)) (*sd.DeregisterInstanceOutput, error)
	DiscoverInstances(ctx context.Context, params *sd.DiscoverInstancesInput, optFns ...func(*sd.Options)) (*sd.DiscoverInstancesOutput, error)
	ListNamespaces(ctx context.Context, params *sd.ListNamespacesInput, optFns ...func(*sd.Options)) (*sd.ListNamespacesOutput, error)
	ListServices(ctx context.Context, params *sd.ListServicesInput, optFns ...func(*sd.Options)) (*sd.ListServicesOutput, error)
	RegisterInstance(ctx context.Context, params *sd.RegisterInstanceInput, optFns ...func(*sd.Options)) (*sd.RegisterInstanceOutput, error)
	UpdateService(ctx context.Context, params *sd.UpdateServiceInput, optFns ...func(*sd.Options)) (*sd.UpdateServiceOutput, error)
	DeleteService(ctx context.Context, params *sd.DeleteServiceInput, optFns ...func(*sd.Options)) (*sd.DeleteServiceOutput, error)
}

// AWSSDProvider is an implementation of Provider for AWS Cloud Map.
type AWSSDProvider struct {
	provider.BaseProvider
	client AWSSDClient
	dryRun bool
	// only consider namespaces ending in this suffix
	namespaceFilter endpoint.DomainFilter
	// filter namespace by type (private or public)
	namespaceTypeFilter sdtypes.NamespaceFilter
	// enables service without instances cleanup
	cleanEmptyService bool
	// filter services for removal
	ownerID string
	// tags to be added to the service
	tags []sdtypes.Tag
}

// NewAWSSDProvider initializes a new AWS Cloud Map based Provider.
func NewAWSSDProvider(domainFilter endpoint.DomainFilter, namespaceType string, dryRun, cleanEmptyService bool, ownerID string, tags map[string]string, client AWSSDClient) (*AWSSDProvider, error) {
	log.Debugf("Initializing AWS Service Discovery provider with domain filter: %v, namespace type: %s, dryRun: %t, cleanEmptyService: %t, ownerID: %s", domainFilter, namespaceType, dryRun, cleanEmptyService, ownerID)

	namespaceTypeFilter := newSdNamespaceFilter(namespaceType)
	awsTagList := awsTags(tags)

	log.Debugf("AWS Service Discovery namespace filter: %v", namespaceTypeFilter)
	if len(tags) > 0 {
		log.Debugf("AWS Service Discovery tags: %v", awsTagList)
	}

	p := &AWSSDProvider{
		client:              client,
		dryRun:              dryRun,
		namespaceFilter:     domainFilter,
		namespaceTypeFilter: namespaceTypeFilter,
		cleanEmptyService:   cleanEmptyService,
		ownerID:             ownerID,
		tags:                awsTagList,
	}

	log.Debugf("AWS Service Discovery provider initialized successfully")

	return p, nil
}

// newSdNamespaceFilter initialized AWS SD Namespace Filter based on given string config
func newSdNamespaceFilter(namespaceTypeConfig string) sdtypes.NamespaceFilter {
	log.Debugf("Creating namespace filter with config: %s", namespaceTypeConfig)

	var filter sdtypes.NamespaceFilter
	switch namespaceTypeConfig {
	case sdNamespaceTypePublic:
		log.Debugf("Using public DNS namespace filter")
		filter = sdtypes.NamespaceFilter{
			Name:   sdtypes.NamespaceFilterNameType,
			Values: []string{string(sdtypes.NamespaceTypeDnsPublic)},
		}
	case sdNamespaceTypePrivate:
		log.Debugf("Using private DNS namespace filter")
		filter = sdtypes.NamespaceFilter{
			Name:   sdtypes.NamespaceFilterNameType,
			Values: []string{string(sdtypes.NamespaceTypeDnsPrivate)},
		}
	default:
		log.Debugf("Using default (empty) namespace filter")
		filter = sdtypes.NamespaceFilter{}
	}

	return filter
}

// awsTags converts user supplied tags to AWS format
func awsTags(tags map[string]string) []sdtypes.Tag {
	log.Debugf("Converting %d user-provided tags to AWS format", len(tags))

	awsTags := make([]sdtypes.Tag, 0, len(tags))
	for k, v := range tags {
		log.Debugf("Converting tag: %s=%s", k, v)
		awsTags = append(awsTags, sdtypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}

	return awsTags
}

// Records returns list of all endpoints.
func (p *AWSSDProvider) Records(ctx context.Context) (endpoints []*endpoint.Endpoint, err error) {
	log.Debug("Fetching records from AWS Service Discovery")

	namespaces, err := p.ListNamespaces(ctx)
	if err != nil {
		log.Errorf("Failed to list namespaces: %v", err)
		return nil, err
	}
	log.Debugf("Found %d matching namespaces", len(namespaces))

	for _, ns := range namespaces {
		log.Debugf("Processing namespace: %s (ID: %s)", *ns.Name, *ns.Id)

		services, err := p.ListServicesByNamespaceID(ctx, ns.Id)
		if err != nil {
			log.Errorf("Failed to list services for namespace %s: %v", *ns.Name, err)
			return nil, err
		}
		log.Debugf("Found %d services in namespace %s", len(services), *ns.Name)

		for srvName, srv := range services {
			log.Debugf("Discovering instances for service: %s", srvName)

			resp, err := p.client.DiscoverInstances(ctx, &sd.DiscoverInstancesInput{
				NamespaceName: ns.Name,
				ServiceName:   srv.Name,
			})
			if err != nil {
				log.Errorf("Failed to discover instances for service %s: %v", *srv.Name, err)
				return nil, err
			}

			if len(resp.Instances) == 0 {
				log.Debugf("No instances found for service %s, attempting to delete", *srv.Name)
				if err := p.DeleteService(ctx, srv); err != nil {
					log.Errorf("Failed to delete service %q, error: %s", *srv.Name, err)
				}
				continue
			}

			log.Debugf("Found %d instances for service %s", len(resp.Instances), *srv.Name)
			endpoints = append(endpoints, p.instancesToEndpoint(ns, srv, resp.Instances))
		}
	}

	log.Debugf("Retrieved %d total endpoints from AWS Service Discovery", len(endpoints))
	return endpoints, nil
}

func (p *AWSSDProvider) instancesToEndpoint(ns *sdtypes.NamespaceSummary, srv *sdtypes.Service, instances []sdtypes.HttpInstanceSummary) *endpoint.Endpoint {
	// DNS name of the record is a concatenation of service and namespace
	recordName := *srv.Name + "." + *ns.Name
	log.Debugf("Creating endpoint for record: %s", recordName)

	labels := endpoint.NewLabels()
	labels[endpoint.AWSSDDescriptionLabel] = *srv.Description

	ttl := endpoint.TTL(*srv.DnsConfig.DnsRecords[0].TTL)
	log.Debugf("Using TTL: %d for record: %s", ttl, recordName)

	newEndpoint := &endpoint.Endpoint{
		DNSName:   recordName,
		RecordTTL: ttl,
		Targets:   make(endpoint.Targets, 0, len(instances)),
		Labels:    labels,
	}

	for i, inst := range instances {
		log.Debugf("Processing instance %d for record %s", i, recordName)

		// CNAME
		if inst.Attributes[sdInstanceAttrCname] != "" && srv.DnsConfig.DnsRecords[0].Type == sdtypes.RecordTypeCname {
			log.Debugf("Adding CNAME target: %s", inst.Attributes[sdInstanceAttrCname])
			newEndpoint.RecordType = endpoint.RecordTypeCNAME
			newEndpoint.Targets = append(newEndpoint.Targets, inst.Attributes[sdInstanceAttrCname])

			// ALIAS
		} else if inst.Attributes[sdInstanceAttrAlias] != "" {
			log.Debugf("Adding ALIAS target: %s", inst.Attributes[sdInstanceAttrAlias])
			newEndpoint.RecordType = endpoint.RecordTypeCNAME
			newEndpoint.Targets = append(newEndpoint.Targets, inst.Attributes[sdInstanceAttrAlias])

			// IPv4-based target
		} else if inst.Attributes[sdInstanceAttrIPV4] != "" {
			log.Debugf("Adding A record target: %s", inst.Attributes[sdInstanceAttrIPV4])
			newEndpoint.RecordType = endpoint.RecordTypeA
			newEndpoint.Targets = append(newEndpoint.Targets, inst.Attributes[sdInstanceAttrIPV4])

			// IPv6-based target
		} else if inst.Attributes[sdInstanceAttrIPV6] != "" {
			log.Debugf("Adding AAAA record target: %s", inst.Attributes[sdInstanceAttrIPV6])
			newEndpoint.RecordType = endpoint.RecordTypeAAAA
			newEndpoint.Targets = append(newEndpoint.Targets, inst.Attributes[sdInstanceAttrIPV6])
		} else {
			log.Warnf("Invalid instance \"%v\" found in service \"%v\"", inst, srv.Name)
		}
	}

	log.Debugf("Created endpoint for %s with record type %s and %d targets", recordName, newEndpoint.RecordType, len(newEndpoint.Targets))
	return newEndpoint
}

// ApplyChanges applies Kubernetes changes in endpoints to AWS API
func (p *AWSSDProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	log.Debug("Applying changes to AWS Service Discovery")
	log.Debugf("Changes to be applied - Create: %d, Update: %d, Delete: %d",
		len(changes.Create), len(changes.UpdateNew), len(changes.Delete))

	// return early if there is nothing to change
	if len(changes.Create) == 0 && len(changes.Delete) == 0 && len(changes.UpdateNew) == 0 {
		log.Info("All records are already up to date")
		return nil
	}

	// convert updates to delete and create operation if applicable (updates not supported)
	log.Debug("Converting updates to create/delete operations")
	creates, deletes := p.updatesToCreates(changes)

	if len(creates) > 0 {
		log.Debugf("Added %d endpoints to create list from updates", len(creates))
		changes.Create = append(changes.Create, creates...)
	}

	if len(deletes) > 0 {
		log.Debugf("Added %d endpoints to delete list from updates", len(deletes))
		changes.Delete = append(changes.Delete, deletes...)
	}

	log.Debugf("Final changes to apply - Create: %d, Delete: %d",
		len(changes.Create), len(changes.Delete))

	log.Debug("Fetching namespaces for change application")
	namespaces, err := p.ListNamespaces(ctx)
	if err != nil {
		log.Errorf("Failed to list namespaces: %v", err)
		return err
	}
	log.Debugf("Found %d namespaces for applying changes", len(namespaces))

	if len(changes.Delete) > 0 {
		log.Debug("Processing deletions")
		err = p.submitDeletes(ctx, namespaces, changes.Delete)
		if err != nil {
			log.Errorf("Failed to submit deletes: %v", err)
			return err
		}
		log.Debug("Successfully processed all deletions")
	}

	if len(changes.Create) > 0 {
		log.Debug("Processing creations")
		err = p.submitCreates(ctx, namespaces, changes.Create)
		if err != nil {
			log.Errorf("Failed to submit creates: %v", err)
			return err
		}
		log.Debug("Successfully processed all creations")
	}

	log.Debug("Successfully applied all changes to AWS Service Discovery")
	return nil
}

func (p *AWSSDProvider) updatesToCreates(changes *plan.Changes) (creates []*endpoint.Endpoint, deletes []*endpoint.Endpoint) {
	log.Debug("Converting update operations to create/delete operations")
	log.Debugf("Processing %d update operations", len(changes.UpdateNew))

	updateNewMap := map[string]*endpoint.Endpoint{}
	for _, e := range changes.UpdateNew {
		log.Debugf("Mapping update for DNS name: %s", e.DNSName)
		updateNewMap[e.DNSName] = e
	}

	for _, old := range changes.UpdateOld {
		current := updateNewMap[old.DNSName]
		log.Debugf("Processing update for DNS name: %s", old.DNSName)

		if !old.Targets.Same(current.Targets) {
			log.Debugf("Targets changed for %s - old: %v, new: %v",
				old.DNSName, old.Targets, current.Targets)

			currentTargetsMap := make(map[string]struct{}, len(current.Targets))
			for _, newTarget := range current.Targets {
				currentTargetsMap[newTarget] = struct{}{}
			}

			// If targets changed, only deregister removed targets (i.e. in `UpdateOld` but not in `UpdateNew`)
			targetsToRemove := make(endpoint.Targets, 0)
			for _, oldTarget := range old.Targets {
				if _, found := currentTargetsMap[oldTarget]; !found {
					log.Debugf("Target to remove: %s from %s", oldTarget, old.DNSName)
					targetsToRemove = append(targetsToRemove, oldTarget)
				}
			}

			if len(targetsToRemove) > 0 {
				log.Debugf("Will remove %d targets from %s", len(targetsToRemove), old.DNSName)
				old.Targets = targetsToRemove
				deletes = append(deletes, old)
			} else {
				log.Debugf("No targets to remove from %s", old.DNSName)
			}
		} else {
			log.Debugf("Targets unchanged for %s", old.DNSName)
		}

		// always register (or re-register) instance with the current data
		log.Debugf("Adding endpoint to create list: %s with %d targets",
			current.DNSName, len(current.Targets))
		creates = append(creates, current)
	}

	log.Debugf("Conversion complete - %d endpoints to create, %d endpoints to delete",
		len(creates), len(deletes))
	return creates, deletes
}

func (p *AWSSDProvider) submitCreates(ctx context.Context, namespaces []*sdtypes.NamespaceSummary, changes []*endpoint.Endpoint) error {
	log.Debug("Submitting endpoint creations to AWS Service Discovery")

	changesByNamespaceID := p.changesByNamespaceID(namespaces, changes)
	log.Debugf("Organized changes into %d namespaces", len(changesByNamespaceID))

	for nsID, changeList := range changesByNamespaceID {
		log.Debugf("Processing %d creations for namespace ID: %s", len(changeList), nsID)

		log.Debug("Listing services for namespace")
		services, err := p.ListServicesByNamespaceID(ctx, aws.String(nsID))
		if err != nil {
			log.Errorf("Failed to list services for namespace ID %s: %v", nsID, err)
			return err
		}
		log.Debugf("Found %d existing services in namespace", len(services))

		for _, ch := range changeList {
			_, srvName := p.parseHostname(ch.DNSName)
			log.Debugf("Processing creation for: %s, service name: %s", ch.DNSName, srvName)

			srv := services[srvName]
			if srv == nil {
				log.Debugf("Service %s does not exist, creating new service", srvName)
				// when service is missing create a new one
				srv, err = p.CreateService(ctx, &nsID, &srvName, ch)
				if err != nil {
					log.Errorf("Failed to create service %s: %v", srvName, err)
					return err
				}
				// update local list of services
				services[*srv.Name] = srv
				log.Debugf("Service %s created successfully with ID: %s", srvName, *srv.Id)
			} else if ch.RecordTTL.IsConfigured() && *srv.DnsConfig.DnsRecords[0].TTL != int64(ch.RecordTTL) {
				log.Debugf("Service %s exists but TTL differs (existing: %d, desired: %d), updating service",
					srvName, *srv.DnsConfig.DnsRecords[0].TTL, int64(ch.RecordTTL))
				// update service when TTL differ
				err = p.UpdateService(ctx, srv, ch)
				if err != nil {
					log.Errorf("Failed to update service %s: %v", srvName, err)
					return err
				}
				log.Debugf("Service %s updated successfully", srvName)
			} else {
				log.Debugf("Service %s exists and TTL matches, no service update needed", srvName)
			}

			log.Debugf("Registering instance for service %s with %d targets", srvName, len(ch.Targets))
			err = p.RegisterInstance(ctx, srv, ch)
			if err != nil {
				log.Errorf("Failed to register instance for service %s: %v", srvName, err)
				return err
			}
			log.Debugf("Successfully registered instance for service %s", srvName)
		}
	}

	log.Debug("Successfully submitted all endpoint creations")
	return nil
}

func (p *AWSSDProvider) submitDeletes(ctx context.Context, namespaces []*sdtypes.NamespaceSummary, changes []*endpoint.Endpoint) error {
	log.Debug("Submitting endpoint deletions to AWS Service Discovery")

	changesByNamespaceID := p.changesByNamespaceID(namespaces, changes)
	log.Debugf("Organized deletions into %d namespaces", len(changesByNamespaceID))

	for nsID, changeList := range changesByNamespaceID {
		log.Debugf("Processing %d deletions for namespace ID: %s", len(changeList), nsID)

		log.Debug("Listing services for namespace")
		services, err := p.ListServicesByNamespaceID(ctx, aws.String(nsID))
		if err != nil {
			log.Errorf("Failed to list services for namespace ID %s: %v", nsID, err)
			return err
		}
		log.Debugf("Found %d existing services in namespace", len(services))

		for _, ch := range changeList {
			hostname := ch.DNSName
			_, srvName := p.parseHostname(hostname)
			log.Debugf("Processing deletion for: %s, service name: %s", hostname, srvName)

			srv := services[srvName]
			if srv == nil {
				log.Errorf("Service %s is missing when trying to delete %s", srvName, hostname)
				return fmt.Errorf("service \"%s\" is missing when trying to delete \"%v\"", srvName, hostname)
			}
			log.Debugf("Found service %s (ID: %s) for deletion", srvName, *srv.Id)

			log.Debugf("Deregistering instance for service %s with %d targets", srvName, len(ch.Targets))
			err := p.DeregisterInstance(ctx, srv, ch)
			if err != nil {
				log.Errorf("Failed to deregister instance for service %s: %v", srvName, err)
				return err
			}
			log.Debugf("Successfully deregistered instance for service %s", srvName)
		}
	}

	log.Debug("Successfully submitted all endpoint deletions")
	return nil
}

// ListNamespaces returns all namespaces matching defined namespace filter
func (p *AWSSDProvider) ListNamespaces(ctx context.Context) ([]*sdtypes.NamespaceSummary, error) {
	log.Debug("Listing namespaces from AWS Service Discovery")

	if p.namespaceTypeFilter.Name != "" {
		log.Debugf("Using namespace type filter: %s with values: %v",
			p.namespaceTypeFilter.Name, p.namespaceTypeFilter.Values)
	} else {
		log.Debug("No namespace type filter applied")
	}

	log.Debugf("Using domain filter: %v", p.namespaceFilter)

	namespaces := make([]*sdtypes.NamespaceSummary, 0)

	log.Debug("Starting namespace pagination")
	paginator := sd.NewListNamespacesPaginator(p.client, &sd.ListNamespacesInput{
		Filters: []sdtypes.NamespaceFilter{p.namespaceTypeFilter},
	})

	pageCount := 0
	for paginator.HasMorePages() {
		pageCount++
		log.Debugf("Fetching namespace page %d", pageCount)

		resp, err := paginator.NextPage(ctx)
		if err != nil {
			log.Errorf("Failed to list namespaces page %d: %v", pageCount, err)
			return nil, err
		}

		log.Debugf("Received %d namespaces in page %d", len(resp.Namespaces), pageCount)

		for _, ns := range resp.Namespaces {
			if !p.namespaceFilter.Match(*ns.Name) {
				log.Debugf("Namespace %s does not match domain filter, skipping", *ns.Name)
				continue
			}
			log.Debugf("Found matching namespace: %s (ID: %s, Type: %s)", *ns.Name, *ns.Id, ns.Type)
			namespaces = append(namespaces, &ns)
		}
	}

	log.Debugf("Found %d matching namespaces after filtering", len(namespaces))
	return namespaces, nil
}

// ListServicesByNamespaceID returns list of services in given namespace.
func (p *AWSSDProvider) ListServicesByNamespaceID(ctx context.Context, namespaceID *string) (map[string]*sdtypes.Service, error) {
	log.Debugf("Listing services for namespace ID: %s", *namespaceID)

	services := make([]sdtypes.ServiceSummary, 0)

	log.Debug("Starting service pagination")
	paginator := sd.NewListServicesPaginator(p.client, &sd.ListServicesInput{
		Filters: []sdtypes.ServiceFilter{{
			Name:   sdtypes.ServiceFilterNameNamespaceId,
			Values: []string{*namespaceID},
		}},
		MaxResults: aws.Int32(100),
	})

	pageCount := 0
	for paginator.HasMorePages() {
		pageCount++
		log.Debugf("Fetching service page %d", pageCount)

		resp, err := paginator.NextPage(ctx)
		if err != nil {
			log.Errorf("Failed to list services page %d: %v", pageCount, err)
			return nil, err
		}

		log.Debugf("Received %d services in page %d", len(resp.Services), pageCount)
		services = append(services, resp.Services...)
	}

	log.Debugf("Found %d total services for namespace ID %s", len(services), *namespaceID)

	servicesMap := make(map[string]*sdtypes.Service)
	for _, serviceSummary := range services {
		log.Debugf("Converting service summary to service: %s (ID: %s)", *serviceSummary.Name, *serviceSummary.Id)

		service := &sdtypes.Service{
			Arn:                     serviceSummary.Arn,
			CreateDate:              serviceSummary.CreateDate,
			Description:             serviceSummary.Description,
			DnsConfig:               serviceSummary.DnsConfig,
			HealthCheckConfig:       serviceSummary.HealthCheckConfig,
			HealthCheckCustomConfig: serviceSummary.HealthCheckCustomConfig,
			Id:                      serviceSummary.Id,
			InstanceCount:           serviceSummary.InstanceCount,
			Name:                    serviceSummary.Name,
			NamespaceId:             namespaceID,
			Type:                    serviceSummary.Type,
		}

		servicesMap[*service.Name] = service
	}

	log.Debugf("Converted %d service summaries to service objects", len(servicesMap))
	return servicesMap, nil
}

// CreateService creates a new service in AWS API. Returns the created service.
func (p *AWSSDProvider) CreateService(ctx context.Context, namespaceID *string, srvName *string, ep *endpoint.Endpoint) (*sdtypes.Service, error) {
	log.Infof("Creating a new service \"%s\" in \"%s\" namespace", *srvName, *namespaceID)
	log.Debugf("Service creation details - DNS Name: %s", ep.DNSName)

	srvType := p.serviceTypeFromEndpoint(ep)
	routingPolicy := p.routingPolicyFromEndpoint(ep)

	log.Debugf("Service type: %s, routing policy: %s", srvType, routingPolicy)

	ttl := int64(sdDefaultRecordTTL)
	if ep.RecordTTL.IsConfigured() {
		ttl = int64(ep.RecordTTL)
		log.Debugf("Using custom TTL from endpoint: %d", ttl)
	} else {
		log.Debugf("Using default TTL: %d", ttl)
	}

	description := ep.Labels[endpoint.AWSSDDescriptionLabel]
	log.Debugf("Service description: %s", description)

	if len(p.tags) > 0 {
		log.Debugf("Applying %d tags to service", len(p.tags))
	}

	if p.dryRun {
		log.Debug("Dry run enabled, skipping actual service creation")
		log.Debug("Would have created service with the following configuration:")
		log.Debugf("  Name: %s", *srvName)
		log.Debugf("  Namespace ID: %s", *namespaceID)
		log.Debugf("  DNS Type: %s", srvType)
		log.Debugf("  TTL: %d", ttl)
		log.Debugf("  Routing Policy: %s", routingPolicy)

		// return mock service summary in case of dry run
		mockService := &sdtypes.Service{Id: aws.String("dry-run-service"), Name: aws.String("dry-run-service")}
		log.Debug("Returning mock service for dry run")
		return mockService, nil
	}

	log.Debug("Creating service in AWS Service Discovery")
	out, err := p.client.CreateService(ctx, &sd.CreateServiceInput{
		Name:        srvName,
		Description: aws.String(description),
		DnsConfig: &sdtypes.DnsConfig{
			RoutingPolicy: routingPolicy,
			DnsRecords: []sdtypes.DnsRecord{{
				Type: srvType,
				TTL:  aws.Int64(ttl),
			}},
		},
		NamespaceId: namespaceID,
		Tags:        p.tags,
	})

	if err != nil {
		log.Errorf("Failed to create service %s: %v", *srvName, err)
		return nil, err
	}

	log.Debugf("Service created successfully with ID: %s", *out.Service.Id)
	return out.Service, nil
}

// UpdateService updates the specified service with information from provided endpoint.
func (p *AWSSDProvider) UpdateService(ctx context.Context, service *sdtypes.Service, ep *endpoint.Endpoint) error {
	log.Infof("Updating service \"%s\"", *service.Name)
	log.Debugf("Service update details - DNS Name: %s, Service ID: %s", ep.DNSName, *service.Id)

	srvType := p.serviceTypeFromEndpoint(ep)
	log.Debugf("Service type for update: %s", srvType)

	ttl := int64(sdDefaultRecordTTL)
	if ep.RecordTTL.IsConfigured() {
		ttl = int64(ep.RecordTTL)
		log.Debugf("Using custom TTL from endpoint: %d", ttl)
	} else {
		log.Debugf("Using default TTL: %d", ttl)
	}

	description := ep.Labels[endpoint.AWSSDDescriptionLabel]
	log.Debugf("Service description for update: %s", description)

	if p.dryRun {
		log.Debug("Dry run enabled, skipping actual service update")
		log.Debug("Would have updated service with the following configuration:")
		log.Debugf("  Service ID: %s", *service.Id)
		log.Debugf("  DNS Type: %s", srvType)
		log.Debugf("  TTL: %d", ttl)
		log.Debugf("  Description: %s", description)
		return nil
	}

	log.Debug("Updating service in AWS Service Discovery")
	_, err := p.client.UpdateService(ctx, &sd.UpdateServiceInput{
		Id: service.Id,
		Service: &sdtypes.ServiceChange{
			Description: aws.String(description),
			DnsConfig: &sdtypes.DnsConfigChange{
				DnsRecords: []sdtypes.DnsRecord{{
					Type: srvType,
					TTL:  aws.Int64(ttl),
				}},
			},
		},
	})

	if err != nil {
		log.Errorf("Failed to update service %s: %v", *service.Name, err)
		return err
	}

	log.Debugf("Service %s updated successfully", *service.Name)
	return nil
}

// DeleteService deletes empty Service from AWS API if its owner id match
func (p *AWSSDProvider) DeleteService(ctx context.Context, service *sdtypes.Service) error {
	log.Debugf("Check if service \"%s\" owner id match and it can be deleted", *service.Name)
	if !p.dryRun && p.cleanEmptyService {
		// convert ownerID string to service description format
		label := endpoint.NewLabels()
		label[endpoint.OwnerLabelKey] = p.ownerID
		label[endpoint.AWSSDDescriptionLabel] = label.SerializePlain(false)

		if strings.HasPrefix(*service.Description, label[endpoint.AWSSDDescriptionLabel]) {
			log.Infof("Deleting service \"%s\"", *service.Name)
			_, err := p.client.DeleteService(ctx, &sd.DeleteServiceInput{
				Id: aws.String(*service.Id),
			})
			return err
		}
		log.Debugf("Skipping service removal %s because owner id does not match, found: \"%s\", required: \"%s\"", *service.Name, *service.Description, label[endpoint.AWSSDDescriptionLabel])
	}
	return nil
}

// RegisterInstance creates a new instance in given service.
func (p *AWSSDProvider) RegisterInstance(ctx context.Context, service *sdtypes.Service, ep *endpoint.Endpoint) error {
	log.Debugf("Starting instance registration for service %s (ID: %s)", *service.Name, *service.Id)
	log.Debugf("Registering instance for DNS name: %s with %d targets", ep.DNSName, len(ep.Targets))

	for i, target := range ep.Targets {
		log.Infof("Registering a new instance \"%s\" for service \"%s\" (%s)", target, *service.Name, *service.Id)
		log.Debugf("Processing target %d/%d: %s", i+1, len(ep.Targets), target)

		attr := make(map[string]string)
		log.Debug("Creating instance attributes")

		switch ep.RecordType {
		case endpoint.RecordTypeCNAME:
			if p.isAWSLoadBalancer(target) {
				log.Debugf("Target is AWS Load Balancer, setting attribute: %s", sdInstanceAttrAlias)
				attr[sdInstanceAttrAlias] = target
			} else {
				log.Debugf("Target is CNAME, setting attribute: %s", sdInstanceAttrCname)
				attr[sdInstanceAttrCname] = target
			}
		case endpoint.RecordTypeA:
			log.Debugf("Target is IPv4, setting attribute: %s", sdInstanceAttrIPV4)
			attr[sdInstanceAttrIPV4] = target
		case endpoint.RecordTypeAAAA:
			log.Debugf("Target is IPv6, setting attribute: %s", sdInstanceAttrIPV6)
			attr[sdInstanceAttrIPV6] = target
		default:
			err := fmt.Errorf("invalid endpoint type (%v)", ep)
			log.Errorf("Invalid endpoint type: %s", ep.RecordType)
			return err
		}

		instanceID := p.targetToInstanceID(target)
		log.Debugf("Generated instance ID: %s for target: %s", instanceID, target)

		if p.dryRun {
			log.Debug("Dry run enabled, skipping actual instance registration")
			log.Debugf("Would have registered instance with the following configuration:")
			log.Debugf("  Service ID: %s", *service.Id)
			log.Debugf("  Instance ID: %s", instanceID)
			for attrKey, attrVal := range attr {
				log.Debugf("  Attribute: %s = %s", attrKey, attrVal)
			}
			continue
		}

		log.Debug("Registering instance in AWS Service Discovery")
		_, err := p.client.RegisterInstance(ctx, &sd.RegisterInstanceInput{
			ServiceId:  service.Id,
			Attributes: attr,
			InstanceId: aws.String(instanceID),
		})
		if err != nil {
			log.Errorf("Failed to register instance for target %s: %v", target, err)
			return err
		}

		log.Debugf("Successfully registered instance with ID: %s for target: %s", instanceID, target)
	}

	log.Debugf("Completed registration of all instances for service %s", *service.Name)
	return nil
}

// DeregisterInstance removes an instance from given service.
func (p *AWSSDProvider) DeregisterInstance(ctx context.Context, service *sdtypes.Service, ep *endpoint.Endpoint) error {
	log.Debugf("Starting instance deregistration for service %s (ID: %s)", *service.Name, *service.Id)
	log.Debugf("Deregistering instances for DNS name: %s with %d targets", ep.DNSName, len(ep.Targets))

	for i, target := range ep.Targets {
		log.Infof("De-registering an instance \"%s\" for service \"%s\" (%s)", target, *service.Name, *service.Id)
		log.Debugf("Processing target %d/%d: %s", i+1, len(ep.Targets), target)

		instanceID := p.targetToInstanceID(target)
		log.Debugf("Generated instance ID: %s for target: %s", instanceID, target)

		if p.dryRun {
			log.Debug("Dry run enabled, skipping actual instance deregistration")
			log.Debugf("Would have deregistered instance with the following configuration:")
			log.Debugf("  Service ID: %s", *service.Id)
			log.Debugf("  Instance ID: %s", instanceID)
			continue
		}

		log.Debug("Deregistering instance from AWS Service Discovery")
		_, err := p.client.DeregisterInstance(ctx, &sd.DeregisterInstanceInput{
			InstanceId: aws.String(instanceID),
			ServiceId:  service.Id,
		})
		if err != nil {
			log.Errorf("Failed to deregister instance for target %s: %v", target, err)
			return err
		}

		log.Debugf("Successfully deregistered instance with ID: %s for target: %s", instanceID, target)
	}

	log.Debugf("Completed deregistration of all instances for service %s", *service.Name)
	return nil
}

// Instance ID length is limited by AWS API to 64 characters. For longer strings SHA-256 hash will be used instead of
// the verbatim target to limit the length.
func (p *AWSSDProvider) targetToInstanceID(target string) string {
	log.Debugf("Converting target to instance ID: %s (length: %d)", target, len(target))

	if len(target) > 64 {
		log.Debugf("Target exceeds 64 character limit, generating SHA-256 hash")
		hash := sha256.Sum256([]byte(strings.ToLower(target)))
		instanceID := hex.EncodeToString(hash[:])
		log.Debugf("Generated hash for target: %s", instanceID)
		return instanceID
	}

	instanceID := strings.ToLower(target)
	log.Debugf("Using lowercase target as instance ID: %s", instanceID)
	return instanceID
}

func (p *AWSSDProvider) changesByNamespaceID(namespaces []*sdtypes.NamespaceSummary, changes []*endpoint.Endpoint) map[string][]*endpoint.Endpoint {
	log.Debugf("Organizing %d changes by namespace ID from %d namespaces", len(changes), len(namespaces))

	changesByNsID := make(map[string][]*endpoint.Endpoint)

	for _, ns := range namespaces {
		log.Debugf("Initializing empty change list for namespace: %s (ID: %s)", *ns.Name, *ns.Id)
		changesByNsID[*ns.Id] = []*endpoint.Endpoint{}
	}

	for i, c := range changes {
		// trim the trailing dot from hostname if any
		hostname := strings.TrimSuffix(c.DNSName, ".")
		log.Debugf("Processing change %d/%d: %s", i+1, len(changes), hostname)

		nsName, srvName := p.parseHostname(hostname)
		log.Debugf("Parsed hostname %s into namespace: %s, service: %s", hostname, nsName, srvName)

		matchingNamespaces := matchingNamespaces(nsName, namespaces)
		if len(matchingNamespaces) == 0 {
			log.Warnf("Skipping record %s because no namespace matching record DNS Name was detected ", c.String())
			continue
		}

		log.Debugf("Found %d matching namespaces for %s", len(matchingNamespaces), nsName)
		for _, ns := range matchingNamespaces {
			log.Debugf("Adding change for %s to namespace %s (ID: %s)", hostname, *ns.Name, *ns.Id)
			changesByNsID[*ns.Id] = append(changesByNsID[*ns.Id], c)
		}
	}

	// separating a change could lead to empty sub changes, remove them here.
	initialCount := len(changesByNsID)
	log.Debugf("Cleaning up empty change lists (initial namespaces: %d)", initialCount)

	for zone, change := range changesByNsID {
		if len(change) == 0 {
			log.Debugf("Removing empty change list for namespace ID: %s", zone)
			delete(changesByNsID, zone)
		} else {
			log.Debugf("Namespace ID %s has %d changes", zone, len(change))
		}
	}

	log.Debugf("Final organization: %d namespaces with changes (removed %d empty)",
		len(changesByNsID), initialCount-len(changesByNsID))

	return changesByNsID
}

// returns list of all namespaces matching given hostname
func matchingNamespaces(hostname string, namespaces []*sdtypes.NamespaceSummary) []*sdtypes.NamespaceSummary {
	log.Debugf("Finding matching namespaces for hostname: %s among %d namespaces", hostname, len(namespaces))
	matchingNamespaces := make([]*sdtypes.NamespaceSummary, 0)

	for i, ns := range namespaces {
		log.Debugf("Checking namespace %d/%d: %s against hostname: %s", i+1, len(namespaces), *ns.Name, hostname)
		if *ns.Name == hostname {
			log.Debugf("Found matching namespace: %s (ID: %s)", *ns.Name, *ns.Id)
			matchingNamespaces = append(matchingNamespaces, ns)
		}
	}

	log.Debugf("Found %d matching namespaces for hostname: %s", len(matchingNamespaces), hostname)
	if len(matchingNamespaces) > 0 {
		for i, ns := range matchingNamespaces {
			log.Debugf("Matching namespace %d/%d: %s (ID: %s)", i+1, len(matchingNamespaces), *ns.Name, *ns.Id)
		}
	} else {
		log.Debugf("No matching namespaces found for hostname: %s", hostname)
	}

	return matchingNamespaces
}

// parse hostname to namespace (domain) and service
func (p *AWSSDProvider) parseHostname(hostname string) (namespace string, service string) {
	parts := strings.Split(hostname, ".")
	service = parts[0]
	namespace = strings.Join(parts[1:], ".")
	return
}

// determine service routing policy based on endpoint type
func (p *AWSSDProvider) routingPolicyFromEndpoint(ep *endpoint.Endpoint) sdtypes.RoutingPolicy {
	if ep.RecordType == endpoint.RecordTypeA || ep.RecordType == endpoint.RecordTypeAAAA {
		return sdtypes.RoutingPolicyMultivalue
	}

	return sdtypes.RoutingPolicyWeighted
}

// determine service type (A, AAAA, CNAME) from given endpoint
func (p *AWSSDProvider) serviceTypeFromEndpoint(ep *endpoint.Endpoint) sdtypes.RecordType {
	switch ep.RecordType {
	case endpoint.RecordTypeCNAME:
		// FIXME service type is derived from the first target only. Theoretically this may be problem.
		// But I don't see a scenario where one endpoint contains targets of different types.
		if p.isAWSLoadBalancer(ep.Targets[0]) {
			// ALIAS target uses DNS record of type A
			return sdtypes.RecordTypeA
		}
		return sdtypes.RecordTypeCname
	case endpoint.RecordTypeAAAA:
		return sdtypes.RecordTypeAaaa
	default:
		return sdtypes.RecordTypeA
	}
}

// determine if a given hostname belongs to an AWS load balancer
func (p *AWSSDProvider) isAWSLoadBalancer(hostname string) bool {
	matchElb := sdElbHostnameRegex.MatchString(hostname)
	matchNlb := sdNlbHostnameRegex.MatchString(hostname)

	return matchElb || matchNlb
}
