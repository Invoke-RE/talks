# Abstract

Supply chain attacks represent one of the most pervasive threats in modern cybersecurity, with the potential to compromise thousands of systems simultaneously. This talk presents a detailed technical analysis of a supply chain compromise campaign, which successfully compromised multiple NPM and PyPI packages within a 10-day period, affecting packages with over 30 million weekly downloads.

We’ll highlight how earlier variants targeted smaller, lesser-known assets before pivoting to high-visibility projects, and how technical similarities across samples linked this operation to previous malware families.

# Description


In July 2025, we observed multiple compromised open-source projects distributing a malware family known as Scavenger. This included popular NPM packages, including eslint-config-prettier, eslint-plugin-prettier, and others. This talk will present our collaborative investigation into Scavenger, a loader–stealer hybrid that leverages phishing and typosquatting to infiltrate developer accounts.

We will walk through our initial discovery of Scavenger, the infection vector embedded in trusted developer tooling, and the phishing campaign that enabled attackers to compromise package maintainer accounts. We’ll highlight how earlier variants targeted smaller, lesser-known assets before pivoting to high-impact projects, and how technical similarities across samples linked this operation to previous malware variants. From anti-analysis techniques and indirect syscalls to the use of encrypted C2 traffic, Scavenger demonstrates the increasing sophistication of adversaries targeting the software supply chain.

Finally, we’ll zoom out to the big picture: how this campaign impacted numerous repositories, what this means for developer trust in open-source, and how the community can build resilience against future incidents. Attendees will leave with an understanding of supply chain attack mechanics, detection strategies, and lessons learned from a weekend spent chasing malware buried inside JavaScript linting tools.

# Presenters

Cedric Brisson, Senior SOC Analyst & Technical Lead, [Coveo](https://www.coveo.com/)

Joshua Reynolds, Founder, [Invoke RE](https://invokere.com/)
