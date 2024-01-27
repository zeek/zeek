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

func writeDB(fname, name string, record mmdbtype.Map, nets ...*net.IPNet) {
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

	_, err = writer.WriteTo(fh)
	if err != nil {
		fh.Close()
		log.Fatal(err)
	}

	fh.Close()
}

func main() {
	_, net1, _ := net.ParseCIDR("128.3.0.0/16")
	_, net2, _ := net.ParseCIDR("131.243.0.0/16")
	_, net3, _ := net.ParseCIDR("2607:f140::/32")

	// The ASN record.
	asnRecord := mmdbtype.Map{}
	asnRecord["autonomous_system_number"] = mmdbtype.Uint32(16)
	asnRecord["autonomous_system_organization"] = mmdbtype.String("Lawrence Berkeley National Laboratory")
	writeDB("GeoLite2-ASN.mmdb", "My-ASN-DB", asnRecord, net1, net2, net3)

	// The Location record.
	locRecord := mmdbtype.Map{
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
	writeDB("GeoLite2-City.mmdb", "My-City-DB", locRecord, net1, net2, net3)
}
