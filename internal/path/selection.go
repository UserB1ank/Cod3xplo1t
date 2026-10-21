package path

// PathSelection is the deterministic explanation attached to one candidate
// path by the path-enhancement stage. It records why the path was retained or
// filtered, which scoring version and weights were used, and the upstream
// identity it came from. A selection is a scheduling decision, never a
// vulnerability verdict or a proof that a filtered path is safe.
type PathSelection struct {
	SchemaVersion    string `json:"schema_version"`
	Selection        string `json:"selection"`
	Reason           string `json:"reason"`
	FilterCode       string `json:"filter_code,omitempty"`
	ScoreVersion     int    `json:"score_version"`
	WeightsDigest    string `json:"weights_digest"`
	SourcePathID     string `json:"source_path_id"`
	SourceArtifactID string `json:"source_artifact_id,omitempty"`
	ProducerID       string `json:"producer_plugin,omitempty"`
	ProducerVersion  string `json:"producer_version,omitempty"`
	InvocationID     string `json:"invocation_id,omitempty"`
}

// EnhancementPath is one selected or filtered path in the enhancement ledger.
type EnhancementPath struct {
	PathID        string        `json:"path_id"`
	EntrySubject  string        `json:"entry_subject"`
	TargetSubject string        `json:"target_subject"`
	EntryNodeID   string        `json:"entry_node_id"`
	TargetNodeID  string        `json:"target_node_id"`
	PathStatus    string        `json:"path_status"`
	Priority      float64       `json:"priority"`
	Risk          float64       `json:"risk"`
	Support       float64       `json:"support"`
	Utility       float64       `json:"utility"`
	ScoreVersion  int           `json:"score_version"`
	Selection     PathSelection `json:"selection"`
	Limitations   []string      `json:"limitations,omitempty"`
}

// EnhancementSummary is the append-only ledger of one deterministic enhancement
// stage. It is persisted on the audit so the path page can explain both retained
// and filtered candidates without pretending the filtered ones were reviewed.
type EnhancementSummary struct {
	SchemaVersion    string            `json:"schema_version"`
	ProducerID       string            `json:"producer_plugin,omitempty"`
	ProducerVersion  string            `json:"producer_version,omitempty"`
	InvocationID     string            `json:"invocation_id,omitempty"`
	ConfigDigest     string            `json:"config_digest,omitempty"`
	InputArtifactIDs []string          `json:"input_artifact_ids,omitempty"`
	ScoreVersion     int               `json:"score_version"`
	WeightsDigest    string            `json:"weights_digest"`
	Selected         []EnhancementPath `json:"selected"`
	Filtered         []EnhancementPath `json:"filtered"`
	Limitations      []string          `json:"limitations"`
}
