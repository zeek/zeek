// Create test MaxMind DB database files containing information about
// just LBL's IPv4 ranges for testing.
package main

import (
	"log"
	"net"
	"os"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func writeDb(fname, name string, record mmdbtype.Map, nets ...*net.IPNet) {
	writer, err := mmdbwriter.New(
		mmdbwriter.Options{
			DatabaseType: name,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	for _, n := range nets {
		if err = writer.Insert(n, record); err != nil {
			log.Fatal(err)
		}
	}

	fh, err := os.Create(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer fh.Close()

	_, err = writer.WriteTo(fh)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	_, net1, _ := net.ParseCIDR("128.3.0.0/16")
	_, net2, _ := net.ParseCIDR("131.243.0.0/16")

	// The ASN record.
	asn_record := mmdbtype.Map{}
	asn_record["autonomous_system_number"] = mmdbtype.Uint32(16)
	asn_record["autonomous_system_organization"] = mmdbtype.String("Lawrence Berkeley National Laboratory")
	writeDb("GeoLite2-ASN.mmdb", "My-ASN-DB", asn_record, net1, net2)

	// The Location record.
	loc_record := mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String("US"),
			"names": mmdbtype.Map{
				"en": mmdbtype.String("United States"),
			},
		},
		"location": mmdbtype.Map{
			"latitude":  mmdbtype.Float64(37.75100),
			"longitude": mmdbtype.Float64(-97.822000),
		},
		"city": mmdbtype.Map{
			"names": mmdbtype.Map{
				"en": mmdbtype.String("Berkeley"),
			},
		},
	}
	writeDb("GeoLite2-City.mmdb", "My-City-DB", loc_record, net1, net2)
}
