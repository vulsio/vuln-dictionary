package nvd

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/k0kubun/pp"
	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/knqyf263/go-version"
)

// Nvd :
type Nvd struct {
	CveDetailID uint `json:"-" xml:"-"`

	// DataType    string
	// DataFormat  string
	// DataVersion string

	CveID        string
	Descriptions []Description

	Cvss2      Cvss2Extra
	Cvss3      Cvss3
	Cwes       []Cwe
	Cpes       []Cpe
	Affects    []Affect
	References []Reference

	// Assigner         string
	PublishedDate    time.Time
	LastModifiedDate time.Time
}

// Cwe has CweID
type Cwe struct {
	NvdXMLID  uint `json:"-" xml:"-"`
	NvdJSONID uint `json:"-" xml:"-"`
	JvnID     uint `json:"-" xml:"-"`

	CweID string
}

// Cpe is Child model of Jvn/Nvd.
// see https://www.ipa.go.jp/security/vuln/CPE.html
// In NVD JSON,
// configurations>nodes>cpe>valunerable: true
type Cpe struct {
	JvnID     uint `json:"-" xml:"-"`
	NvdXMLID  uint `json:"-" xml:"-"`
	NvdJSONID uint `json:"-" xml:"-"`

	CpeBase
	EnvCpes []EnvCpe
}

// EnvCpe is a Environmental CPE
// Only NVD JSON has this information.
// configurations>nodes>cpe>valunerable: false
type EnvCpe struct {
	gorm.Model `json:"-" xml:"-"`
	CpeID      uint `json:"-" xml:"-"`

	CpeBase
}

// CpeBase has common args of Cpe and EnvCpe
type CpeBase struct {
	URI             string
	FormattedString string
	WellFormedName  string `sql:"type:text"`
	CpeWFN

	VersionStartExcluding string
	VersionStartIncluding string
	VersionEndExcluding   string
	VersionEndIncluding   string
}

// CpeWFN has CPE Well Formed name informaiton
type CpeWFN struct {
	Part            string
	Vendor          string
	Product         string
	Version         string
	Update          string
	Edition         string
	Language        string
	SoftwareEdition string
	TargetSW        string
	TargetHW        string
	Other           string
}

// Reference is Child model of Jvn/Nvd.
// It holds reference information about the CVE.
type Reference struct {
	NvdJSONID uint `json:"-" xml:"-"`
	JvnID     uint `json:"-" xml:"-"`

	Source string
	Link   string `sql:"type:text"`
}

// Affect has vendor/product/version info in NVD JSON
type Affect struct {
	NvdJSONID uint `json:"-" xml:"-"`

	Vendor  string
	Product string
	Version string
}

// Cvss3 has CVSS Version 3 info
// NVD JSON and JVN has CVSS3 info
type Cvss3 struct {
	NvdJSONID uint `json:"-" xml:"-"`
	JVNID     uint `json:"-" xml:"-"`

	VectorString string

	AttackVector          string
	AttackComplexity      string
	PrivilegesRequired    string
	UserInteraction       string
	Scope                 string
	ConfidentialityImpact string
	IntegrityImpact       string
	AvailabilityImpact    string

	BaseScore           float64
	BaseSeverity        string
	ExploitabilityScore float64
	ImpactScore         float64
}

// Cvss2 has CVSS Version 2 info
type Cvss2 struct {
	JvnID uint `json:"-" xml:"-"`

	VectorString          string
	AccessVector          string
	AccessComplexity      string
	Authentication        string
	ConfidentialityImpact string
	IntegrityImpact       string
	AvailabilityImpact    string
	BaseScore             float64

	// NVD JSON and JVN has severity (Not in NVD XML)
	Severity string
}

// Cvss2Extra has extra CVSS V2 info
type Cvss2Extra struct {
	NvdJSONID uint `json:"-" xml:"-"`

	Cvss2
	ExploitabilityScore     float64
	ImpactScore             float64
	ObtainAllPrivilege      bool
	ObtainUserPrivilege     bool
	ObtainOtherPrivilege    bool
	UserInteractionRequired bool
}

// Description has description of the CVE
type Description struct {
	NvdJSONID uint `json:"-" xml:"-"`

	Lang  string
	Value string `sql:"type:text"`
}

// ConvertToModel converts Nvd JSON to model structure.
func ConvertToModel(item *RawCveItem) (*Nvd, error) {
	//References
	refs := []Reference{}
	for _, r := range item.Cve.References.ReferenceData {
		ref := Reference{
			Link: r.URL,
		}
		refs = append(refs, ref)
	}

	// Cwes
	cwes := []Cwe{}
	for _, data := range item.Cve.Problemtype.ProblemtypeData {
		for _, desc := range data.Description {
			cwes = append(cwes, Cwe{
				CweID: desc.Value,
			})
		}
	}

	// Affects
	affects := []Affect{}
	for _, vendor := range item.Cve.Affects.Vendor.VendorData {
		for _, prod := range vendor.Product.ProductData {
			for _, version := range prod.Version.VersionData {
				affects = append(affects, Affect{
					Vendor:  vendor.VendorName,
					Product: prod.ProductName,
					Version: version.VersionValue,
				})
			}
		}
	}

	// Traverse Cpe, EnvCpe
	cpes := []Cpe{}
	for _, node := range item.Configurations.Nodes {
		if node.Negate {
			continue
		}

		nodeCpes := []Cpe{}
		for _, cpe := range node.Cpes {
			if !cpe.Vulnerable {
				// CVE-2017-14492 and CVE-2017-8581 has a cpe that has vulenrable:false.
				// But these vulnerable: false cpe is also vulnerable...
				// So, ignore the vulerable flag of this layer(under nodes>cpe)
			}
			cpeBase, err := ParseCpeURI(cpe.Cpe23URI)
			if err != nil {
				// logging only
				log.Printf("Failed to parse CpeURI %s: %s", cpe.Cpe23URI, err)
				continue
			}
			cpeBase.VersionStartExcluding = cpe.VersionStartExcluding
			cpeBase.VersionStartIncluding = cpe.VersionStartIncluding
			cpeBase.VersionEndExcluding = cpe.VersionEndExcluding
			cpeBase.VersionEndIncluding = cpe.VersionEndIncluding
			nodeCpes = append(nodeCpes, Cpe{
				CpeBase: *cpeBase,
			})
			if !checkIfVersionParsable(cpeBase) {
				return nil, fmt.Errorf(
					"Version parse err. Please add a issue on [GitHub](https://github.com/kotakanbe/go-cve-dictionary/issues/new). Title: %s, Content:%s",
					item.Cve.CveDataMeta.ID,
					pp.Sprintf("%v", *item),
				)
			}
		}
		for _, child := range node.Children {
			for _, cpe := range child.Cpes {
				if cpe.Vulnerable {
					cpeBase, err := ParseCpeURI(cpe.Cpe23URI)
					if err != nil {
						return nil, err
					}
					cpeBase.VersionStartExcluding = cpe.VersionStartExcluding
					cpeBase.VersionStartIncluding = cpe.VersionStartIncluding
					cpeBase.VersionEndExcluding = cpe.VersionEndExcluding
					cpeBase.VersionEndIncluding = cpe.VersionEndIncluding
					nodeCpes = append(nodeCpes, Cpe{
						CpeBase: *cpeBase,
					})
					if !checkIfVersionParsable(cpeBase) {
						return nil, fmt.Errorf(
							"Version parse err. Please add a issue on [GitHub](https://github.com/kotakanbe/go-cve-dictionary/issues/new). Title: %s, Content:%s",
							item.Cve.CveDataMeta.ID,
							pp.Sprintf("%v", *item),
						)
					}
				} else {
					if node.Operator == "AND" {
						for i, c := range nodeCpes {
							cpeBase, err := ParseCpeURI(cpe.Cpe23URI)
							if err != nil {
								return nil, err
							}
							cpeBase.VersionStartExcluding = cpe.VersionStartExcluding
							cpeBase.VersionStartIncluding = cpe.VersionStartIncluding
							cpeBase.VersionEndExcluding = cpe.VersionEndExcluding
							cpeBase.VersionEndIncluding = cpe.VersionEndIncluding
							nodeCpes[i].EnvCpes = append(c.EnvCpes, EnvCpe{
								CpeBase: *cpeBase,
							})

							if !checkIfVersionParsable(cpeBase) {
								return nil, fmt.Errorf(
									"Please add a issue on [GitHub](https://github.com/kotakanbe/go-cve-dictionary/issues/new). Title: Version parse err: %s, Content:%s",
									item.Cve.CveDataMeta.ID,
									pp.Sprintf("%v", *item),
								)
							}
						}
					}
				}
			}
		}
		cpes = append(cpes, nodeCpes...)
	}

	// Description
	descs := []Description{}
	for _, desc := range item.Cve.Description.DescriptionData {
		descs = append(descs, Description{
			Lang:  desc.Lang,
			Value: desc.Value,
		})
	}

	publish, err := parseNvdJSONTime(item.PublishedDate)
	if err != nil {
		return nil, err
	}
	modified, err := parseNvdJSONTime(item.LastModifiedDate)
	if err != nil {
		return nil, err
	}
	c2 := item.Impact.BaseMetricV2
	c3 := item.Impact.BaseMetricV3

	return &Nvd{
		CveID:        item.Cve.CveDataMeta.ID,
		Descriptions: descs,
		Cvss2: Cvss2Extra{
			Cvss2: Cvss2{
				VectorString:          c2.CvssV2.VectorString,
				AccessVector:          c2.CvssV2.AccessVector,
				AccessComplexity:      c2.CvssV2.AccessComplexity,
				Authentication:        c2.CvssV2.Authentication,
				ConfidentialityImpact: c2.CvssV2.ConfidentialityImpact,
				IntegrityImpact:       c2.CvssV2.IntegrityImpact,
				AvailabilityImpact:    c2.CvssV2.AvailabilityImpact,
				BaseScore:             c2.CvssV2.BaseScore,
				Severity:              c2.Severity,
			},
			ExploitabilityScore:     c2.ExploitabilityScore,
			ImpactScore:             c2.ImpactScore,
			ObtainAllPrivilege:      c2.ObtainAllPrivilege,
			ObtainUserPrivilege:     c2.ObtainUserPrivilege,
			ObtainOtherPrivilege:    c2.ObtainOtherPrivilege,
			UserInteractionRequired: c2.UserInteractionRequired,
		},
		Cvss3: Cvss3{
			VectorString:          c3.CvssV3.VectorString,
			AttackVector:          c3.CvssV3.AttackVector,
			AttackComplexity:      c3.CvssV3.AttackComplexity,
			PrivilegesRequired:    c3.CvssV3.PrivilegesRequired,
			UserInteraction:       c3.CvssV3.UserInteraction,
			Scope:                 c3.CvssV3.Scope,
			ConfidentialityImpact: c3.CvssV3.ConfidentialityImpact,
			IntegrityImpact:       c3.CvssV3.IntegrityImpact,
			AvailabilityImpact:    c3.CvssV3.AvailabilityImpact,
			BaseScore:             c3.CvssV3.BaseScore,
			BaseSeverity:          c3.CvssV3.BaseSeverity,
			ExploitabilityScore:   c3.ExploitabilityScore,
			ImpactScore:           c3.ImpactScore,
		},
		Cwes:             cwes,
		Cpes:             cpes,
		References:       refs,
		Affects:          affects,
		PublishedDate:    publish,
		LastModifiedDate: modified,
	}, nil
}

func checkIfVersionParsable(cpeBase *CpeBase) bool {
	if cpeBase.Version != "ANY" && cpeBase.Version != "NA" {
		vers := []string{cpeBase.VersionStartExcluding,
			cpeBase.VersionStartIncluding,
			cpeBase.VersionEndIncluding,
			cpeBase.VersionEndExcluding}
		for _, v := range vers {
			if v == "" {
				continue
			}
			v := strings.Replace(v, `\`, "", -1)
			if _, err := version.NewVersion(v); err != nil {
				return false
			}
		}
	}
	return true
}

func parseNvdJSONTime(strtime string) (t time.Time, err error) {
	layout := "2006-01-02T15:04Z"
	t, err = time.Parse(layout, strtime)
	if err != nil {
		return t, fmt.Errorf("Failed to parse time, time: %s, err: %s",
			strtime, err)
	}
	return
}

// ParseCpeURI parses cpe22uri and set to models.CpeBase
func ParseCpeURI(uri string) (*CpeBase, error) {
	var wfn common.WellFormedName
	var err error
	if strings.HasPrefix(uri, "cpe:/") {
		val := strings.TrimPrefix(uri, "cpe:/")
		if strings.Contains(val, "/") {
			uri = "cpe:/" + strings.Replace(val, "/", `\/`, -1)
		}
		wfn, err = naming.UnbindURI(uri)
		if err != nil {
			return nil, err
		}
	} else {
		wfn, err = naming.UnbindFS(uri)
		if err != nil {
			return nil, err
		}
	}

	return &CpeBase{
		URI:             naming.BindToURI(wfn),
		FormattedString: naming.BindToFS(wfn),
		WellFormedName:  wfn.String(),
		CpeWFN: CpeWFN{
			Part:            fmt.Sprintf("%s", wfn.Get(common.AttributePart)),
			Vendor:          fmt.Sprintf("%s", wfn.Get(common.AttributeVendor)),
			Product:         fmt.Sprintf("%s", wfn.Get(common.AttributeProduct)),
			Version:         fmt.Sprintf("%s", wfn.Get(common.AttributeVersion)),
			Update:          fmt.Sprintf("%s", wfn.Get(common.AttributeUpdate)),
			Edition:         fmt.Sprintf("%s", wfn.Get(common.AttributeEdition)),
			Language:        fmt.Sprintf("%s", wfn.Get(common.AttributeLanguage)),
			SoftwareEdition: fmt.Sprintf("%s", wfn.Get(common.AttributeSwEdition)),
			TargetSW:        fmt.Sprintf("%s", wfn.Get(common.AttributeTargetSw)),
			TargetHW:        fmt.Sprintf("%s", wfn.Get(common.AttributeTargetHw)),
			Other:           fmt.Sprintf("%s", wfn.Get(common.AttributeOther)),
		},
	}, nil
}
