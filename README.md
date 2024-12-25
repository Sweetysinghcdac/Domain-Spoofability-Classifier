This Python script classifies domains as spoofable or not spoofable based on their DMARC records. It checks each domain’s DMARC policy and separates them into two CSV files:

Not Spoofable: Strong DMARC policy (e.g., p=reject, p=quarantine).
Spoofable: Weak or no DMARC policy.


Features
Classifies domains based on DMARC policy.
Generates two CSV files:
spoofable_domains.csv
not_spoofable_domains.csv


Requirements
Python 3.x
dnspython library: pip install dnspython


Installation
Clone the repo:
bash
Copy code
git clone https://github.com/yourusername/domain-spoofability-classifier.git
Install dependencies:

pip install -r requirements.txt


Usage
Run the script:
python domain_spoofability_classifier.py
Enter the path to the input CSV file and the output folder.