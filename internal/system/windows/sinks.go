package windows

const (
	ReservedSinkMetric     = uint32(65535)
	SinkPolicyStore        = "PersistentStore"
	LoopbackInterfaceIndex = 1
)

type SinkArtifact struct {
	Version  int         `json:"version"`
	Owner    string      `json:"owner"`
	Revision string      `json:"revision"`
	Routes   []SinkRoute `json:"routes"`
}

type SinkRoute struct {
	Family         AddressFamily `json:"family"`
	Destination    string        `json:"destination"`
	NextHop        string        `json:"next_hop"`
	InterfaceIndex int           `json:"interface_index"`
	Metric         uint32        `json:"metric"`
	PolicyStore    string        `json:"policy_store"`
	Protocol       string        `json:"protocol"`
	JournalOwned   bool          `json:"journal_owned"`
}

type SinkState struct {
	Route             SinkRoute `json:"route"`
	Owner             string    `json:"owner,omitempty"`
	Revision          string    `json:"revision,omitempty"`
	PersistentPresent bool      `json:"persistent_present"`
	ActivePresent     bool      `json:"active_present"`
}

type ResolvedRoute struct {
	Family         AddressFamily `json:"family"`
	Destination    string        `json:"destination"`
	InterfaceGUID  string        `json:"interface_guid,omitempty"`
	InterfaceIndex int           `json:"interface_index"`
	NextHop        string        `json:"next_hop"`
	RouteMetric    uint32        `json:"route_metric"`
	NoRoute        bool          `json:"no_route,omitempty"`
}

func sinkForVPNRoute(route ManagedRoute) SinkRoute {
	nextHop := "0.0.0.0"
	if route.Family == FamilyIPv6 {
		nextHop = "::"
	}
	return SinkRoute{
		Family:         route.Family,
		Destination:    route.Destination,
		NextHop:        nextHop,
		InterfaceIndex: LoopbackInterfaceIndex,
		Metric:         ReservedSinkMetric,
		PolicyStore:    SinkPolicyStore,
		Protocol:       RouteProtocol,
		JournalOwned:   true,
	}
}
