package nvd

// RawNvdJSON is a struct of NVD JSON
// https://scap.nist.gov/schema/nvd/feed/0.1/nvd_cve_feed_json_0.1_beta.schema
type RawNvdJSON struct {
	CveDataType         string       `json:"CVE_data_type"`
	CveDataFormat       string       `json:"CVE_data_format"`
	CveDataVersion      string       `json:"CVE_data_version"`
	CveDataNumberOfCVEs string       `json:"CVE_data_numberOfCVEs"`
	CveDataTimestamp    string       `json:"CVE_data_timestamp"`
	CveItems            []RawCveItem `json:"CVE_Items"`
}

// RawCveItem is a struct of NvdJSON>CveItems
type RawCveItem struct {
	Cve struct {
		DataType    string `json:"data_type"`
		DataFormat  string `json:"data_format"`
		DataVersion string `json:"data_version"`
		CveDataMeta struct {
			ID       string `json:"ID"`
			ASSIGNER string `json:"ASSIGNER"`
		} `json:"CVE_data_meta"`
		Affects struct {
			Vendor struct {
				VendorData []struct {
					VendorName string `json:"vendor_name"`
					Product    struct {
						ProductData []struct {
							ProductName string `json:"product_name"`
							Version     struct {
								VersionData []struct {
									VersionValue string `json:"version_value"`
								} `json:"version_data"`
							} `json:"version"`
						} `json:"product_data"`
					} `json:"product"`
				} `json:"vendor_data"`
			} `json:"vendor"`
		} `json:"affects"`
		Problemtype struct {
			ProblemtypeData []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"problemtype_data"`
		} `json:"problemtype"`
		References struct {
			ReferenceData []struct {
				URL string `json:"url"`
			} `json:"reference_data"`
		} `json:"references"`
		Description struct {
			DescriptionData []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description_data"`
		} `json:"description"`
	} `json:"cve"`
	Configurations struct {
		CveDataVersion string `json:"CVE_data_version"`
		Nodes          []struct {
			Operator string `json:"operator"`
			Negate   bool   `json:"negate"`
			Cpes     []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Cpe23URI              string `json:"cpe23Uri"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
			} `json:"cpe_match"`
			Children []struct {
				Operator string `json:"operator"`
				Cpes     []struct {
					Vulnerable            bool   `json:"vulnerable"`
					Cpe23URI              string `json:"cpe23Uri"`
					VersionStartExcluding string `json:"versionStartExcluding"`
					VersionStartIncluding string `json:"versionStartIncluding"`
					VersionEndExcluding   string `json:"versionEndExcluding"`
					VersionEndIncluding   string `json:"versionEndIncluding"`
				} `json:"cpe_match"`
			} `json:"children,omitempty"`
		} `json:"nodes"`
	} `json:"configurations"`
	Impact struct {
		BaseMetricV3 struct {
			CvssV3 struct {
				Version               string  `json:"version"`
				VectorString          string  `json:"vectorString"`
				AttackVector          string  `json:"attackVector"`
				AttackComplexity      string  `json:"attackComplexity"`
				PrivilegesRequired    string  `json:"privilegesRequired"`
				UserInteraction       string  `json:"userInteraction"`
				Scope                 string  `json:"scope"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
				BaseSeverity          string  `json:"baseSeverity"`
			} `json:"cvssV3"`
			ExploitabilityScore float64 `json:"exploitabilityScore"`
			ImpactScore         float64 `json:"impactScore"`
		} `json:"baseMetricV3"`
		BaseMetricV2 struct {
			CvssV2 struct {
				Version               string  `json:"version"`
				VectorString          string  `json:"vectorString"`
				AccessVector          string  `json:"accessVector"`
				AccessComplexity      string  `json:"accessComplexity"`
				Authentication        string  `json:"authentication"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
			} `json:"cvssV2"`
			Severity                string  `json:"severity"`
			ExploitabilityScore     float64 `json:"exploitabilityScore"`
			ImpactScore             float64 `json:"impactScore"`
			ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
			ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
			ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
			UserInteractionRequired bool    `json:"userInteractionRequired"`
		} `json:"baseMetricV2"`
	} `json:"impact"`
	PublishedDate    string `json:"publishedDate"`
	LastModifiedDate string `json:"lastModifiedDate"`
}
