#!/usr/bin/env python3
"""Lists every open SonarCloud issue and unreviewed security hotspot for this
pull request (or branch) and fails if there is any: maintainability,
reliability and security findings all gate, not only the quality gate's
rating thresholds.

Env: SONAR_TOKEN, SONAR_SCOPE ("pullRequest=<n>" or "branch=<name>").
"""
import base64
import json
import os
import re
import sys
import urllib.request

HOST = "https://sonarcloud.io"


def project_key():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    with open(os.path.join(root, "sonar-project.properties")) as f:
        return re.search(r"^sonar\.projectKey=(.+)$", f.read(), re.M).group(1).strip()


def fetch(path):
    request = urllib.request.Request(HOST + "/api/" + path)
    token = base64.b64encode((os.environ["SONAR_TOKEN"] + ":").encode()).decode()
    request.add_header("Authorization", "Basic " + token)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def location(item):
    return "%s:%s" % (item["component"].split(":", 1)[-1], item.get("line", "-"))


def main():
    key = project_key()
    scope = os.environ["SONAR_SCOPE"]
    issues = fetch("issues/search?componentKeys=%s&%s&resolved=false&ps=500" % (key, scope))
    hotspots = fetch("hotspots/search?projectKey=%s&%s&status=TO_REVIEW&ps=500" % (key, scope))
    for i in issues.get("issues", []):
        print("ISSUE   %-8s %-18s %s  %s" % (i.get("severity", ""), i["rule"], location(i), i["message"]))
    for h in hotspots.get("hotspots", []):
        print("HOTSPOT %-8s %-18s %s  %s" % (h.get("vulnerabilityProbability", ""), h.get("ruleKey", ""),
                                            location(h), h["message"]))
    issue_count = issues.get("total", 0)
    hotspot_count = hotspots.get("paging", {}).get("total", 0)
    print("%d open issues, %d hotspots to review" % (issue_count, hotspot_count))
    return 1 if issue_count or hotspot_count else 0


if __name__ == "__main__":
    sys.exit(main())
