import csv
import dns.resolver
import os

def check_dmarc_policy(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            if 'v=DMARC1' in str(rdata):
                dmarc_record = str(rdata)
                if 'p=quarantine' in dmarc_record or 'p=reject' in dmarc_record:
                    return {"status": "Not Spoofable", "record": dmarc_record}
                elif 'p=none' in dmarc_record:
                    return {"status": "Potentially Spoofable", "record": dmarc_record}
                else:
                    return {"status": "Spoofable", "record": dmarc_record}
        return {"status": "Spoofable (No DMARC Record Found)"}
    except dns.resolver.NoAnswer:
        return {"status": "Spoofable (No Answer from DNS)"}
    except dns.resolver.NXDOMAIN:
        return {"status": "Spoofable (Domain Not Found)"}
    except Exception as e:
        return {"status": f"Error: {e}"}

def process_domains(input_file, output_folder):
    spoofable_domains = []
    not_spoofable_domains = []

    with open(input_file, mode='r') as csvfile:
        csvreader = csv.reader(csvfile)
        next(csvreader) 
        for row in csvreader:
            if row:
                domain = row[0].strip()
                result = check_dmarc_policy(domain)
                if result["status"] == "Not Spoofable":
                    not_spoofable_domains.append({"domain": domain, "record": result["record"]})
                else:
                    spoofable_domains.append({"domain": domain, "record": result.get("record", "No Record")})

    # Write spoofable domains to CSV
    spoofable_file = os.path.join(output_folder, "spoofable_domains.csv")
    with open(spoofable_file, mode='w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["Domain", "Reason"])
        for item in spoofable_domains:
            csvwriter.writerow([item["domain"], item["record"]])

    # Write not spoofable domains to CSV
    not_spoofable_file = os.path.join(output_folder, "not_spoofable_domains.csv")
    with open(not_spoofable_file, mode='w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["Domain", "DMARC Record"])
        for item in not_spoofable_domains:
            csvwriter.writerow([item["domain"], item["record"]])

    print(f"Spoofable domains saved to {spoofable_file}")
    print(f"Not spoofable domains saved to {not_spoofable_file}")

# usage
if __name__ == "__main__":
    input_file = input("Enter the path to the CSV file containing domains: ")
    output_folder = input("Enter the folder to save the output files: ")

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    process_domains(input_file, output_folder)